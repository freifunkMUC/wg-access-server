package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/freifunkMUC/pg-events/pkg/pgevents"
	"github.com/sirupsen/logrus"
)

// updateTriggerSuffix names the trigger that reports the updates that matter.
// pg-events installs its own trigger for inserts and deletes; this one sits
// next to it.
const updateTriggerSuffix = "_update_events"

// legacyRenameTriggerSuffix is what the same trigger was called while it only
// reported renames. It is dropped, so an upgraded database does not end up
// notifying twice per rename.
const legacyRenameTriggerSuffix = "_rename_events"

// setupTimeout bounds connecting to Postgres and installing the trigger. The
// storage backend is opened without a context of its own, and a database that
// does not answer should fail the start rather than hold it open forever.
const setupTimeout = 30 * time.Second

type PgWatcher struct {
	*pgevents.Listener
}

func NewPgWatcher(db *sql.DB, connectionString string, table string, usersTable string) (*PgWatcher, error) {
	logrus.Debug("creating postgres watcher")

	// The context is for getting started only: once the listener is open it
	// runs until it is closed, whatever becomes of this one.
	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()

	listener, err := pgevents.OpenListener(ctx, connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open pg listener: %w", err)
	}

	// Only inserts and deletes are acted on through pg-events (see OnAdd).
	// Without UPDATE in its trigger, the metadata sync - one UPDATE per
	// active device every 30s on every replica - no longer broadcasts each
	// row to all replicas.
	//
	// Without the row: a notification reaches every connection that listens,
	// and Postgres applies no table privileges to it, so any user who may
	// connect to this database would otherwise read every device as it is
	// written - addresses, owner identities, pre-shared keys. The replicas
	// are told that something changed and read the devices themselves, as
	// the user this server connects as.
	if err := listener.AttachWithoutRow(ctx, table, pgevents.Insert, pgevents.Delete); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("failed to attach listener to table: %s: %w", table, err)
	}

	// Who is in which access policy is written when somebody signs in, and it
	// decides what their devices may reach. A replica that took no part in
	// that sign-in has to hear about it, or it would keep building the
	// firewall rules from what it knew before. Without the row, like the
	// devices: the reader looks the users up itself.
	if err := listener.AttachWithoutRow(ctx, usersTable, pgevents.Insert, pgevents.Update, pgevents.Delete); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("failed to attach listener to table: %s: %w", usersTable, err)
	}

	if err := attachUpdateTrigger(db, table); err != nil {
		_ = listener.Close()
		return nil, err
	}

	return &PgWatcher{
		Listener: listener,
	}, nil
}

// attachUpdateTrigger reports the updates that matter: a device that was
// renamed, one whose access changed, one whose routes changed, and one that
// was given new key material - the last of those decides which peer reaches
// the VPN, so a replica that misses it keeps the replaced key working.
// "AFTER UPDATE OF ..." fires only when a statement assigns one of those
// columns, so the metadata sync - which writes the traffic counters and the
// handshake time - stays silent. The trigger reuses the function and the
// channel pg-events set up, so the events arrive through the same listener.
//
// It is dropped and created again on every start, so an installation upgraded
// from a version whose trigger named fewer columns gets the new one.
func attachUpdateTrigger(db *sql.DB, table string) error {
	trigger := table + updateTriggerSuffix

	for _, name := range []string{trigger, table + legacyRenameTriggerSuffix} {
		if _, err := db.Exec(fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON %s", name, table)); err != nil {
			return fmt.Errorf("failed to drop the update trigger on %s: %w", table, err)
		}
	}
	statement := fmt.Sprintf(
		"CREATE TRIGGER %s AFTER UPDATE OF name, disabled, expires_at, routes, public_key, preshared_key "+
			"ON %s FOR EACH ROW EXECUTE PROCEDURE pgevents_notify_event('norow')",
		trigger, table)
	if _, err := db.Exec(statement); err != nil {
		return fmt.Errorf("failed to create the update trigger on %s: %w", table, err)
	}

	return nil
}

// OnAdd, OnUpdate and OnDelete report a device only when an event carries one,
// which the triggers this version installs never ask for. They are still here
// for the moment after an upgrade in which an older version's trigger is still
// on the table: its events carry the row, and dropping them would leave a
// device without a peer until the next resynchronization.
func (w *PgWatcher) OnAdd(cb Callback) {
	w.OnEvent(func(event *pgevents.TableEvent) {
		// Only an insert is an "add": a new device. A device whose key
		// changed is an update, and the peer of the key it had is taken away
		// by the synchronization that follows - which is the one place that
		// knows a peer no device claims any more.
		if event.Action == "INSERT" && !event.Truncated {
			w.emit(cb, event)
		}
	})
}

func (w *PgWatcher) OnUpdate(cb Callback) {
	w.OnEvent(func(event *pgevents.TableEvent) {
		// only the update trigger reports updates, see attachUpdateTrigger
		if event.Action == "UPDATE" && !event.Truncated {
			w.emit(cb, event)
		}
	})
}

func (w *PgWatcher) OnDelete(cb Callback) {
	w.OnEvent(func(event *pgevents.TableEvent) {
		if event.Action == "DELETE" && !event.Truncated {
			w.emit(cb, event)
		}
	})
}

func (w *PgWatcher) OnReconnect(cb func()) {
	w.Listener.OnReconnect(cb)

	// Every event arrives without its row - that is what the triggers ask for,
	// see NewPgWatcher - so there is nothing to add or remove directly.
	// Resynchronize instead, as after a reconnect that may have missed events:
	// the devices are read from the database, where privileges apply.
	//
	// A row too large for a notification (8000 bytes) arrives the same way, so
	// this covers that too.
	w.OnEvent(func(event *pgevents.TableEvent) {
		if event.Truncated {
			logrus.Debugf("a %s on %s was reported without its row; resynchronizing devices", event.Action, event.Table)
			cb()
		}
	})
}

func (w *PgWatcher) emit(cb Callback, event *pgevents.TableEvent) {
	device := &Device{}
	if err := json.Unmarshal([]byte(event.Data), device); err != nil {
		logrus.Error(fmt.Errorf("failed to unmarshal postgres event data into device struct: %w", err))
	} else {
		cb(device)
	}
}

func (w *PgWatcher) EmitAdd(device *Device) {
	// noop because we rely on postgres channels
}

func (w *PgWatcher) EmitUpdate(device *Device) {
	// noop because the database trigger tells every replica, including this one
}

func (w *PgWatcher) EmitDelete(device *Device) {
	// noop because we rely on postgres channels
}

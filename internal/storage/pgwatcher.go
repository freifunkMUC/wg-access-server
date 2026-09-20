package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/freifunkMUC/pg-events/pkg/pgevents"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// renameTriggerSuffix names the trigger that reports renames. pg-events
// installs its own trigger for inserts and deletes; this one sits next to it.
const renameTriggerSuffix = "_rename_events"

type PgWatcher struct {
	*pgevents.Listener
}

func NewPgWatcher(db *sql.DB, connectionString string, table string) (*PgWatcher, error) {
	logrus.Debug("creating postgres watcher")
	listener, err := pgevents.OpenListener(connectionString)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open pg listener")
	}

	// Only inserts and deletes are acted on through pg-events (see OnAdd).
	// Without UPDATE in its trigger, the metadata sync - one UPDATE per
	// active device every 30s on every replica - no longer broadcasts each
	// row to all replicas.
	if err := listener.AttachActions(table, pgevents.Insert, pgevents.Delete); err != nil {
		_ = listener.Close()
		return nil, errors.Wrapf(err, "failed to attach listener to table: %s", table)
	}

	if err := attachRenameTrigger(db, table); err != nil {
		_ = listener.Close()
		return nil, err
	}

	return &PgWatcher{
		Listener: listener,
	}, nil
}

// attachRenameTrigger reports the one kind of update that matters: a device
// that was renamed. "AFTER UPDATE OF name" fires only when a statement
// assigns that column, so the metadata sync - which writes the traffic
// counters and the handshake time - stays silent. The trigger reuses the
// function and the channel pg-events set up, so the events arrive through the
// same listener.
func attachRenameTrigger(db *sql.DB, table string) error {
	trigger := table + renameTriggerSuffix

	if _, err := db.Exec(fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON %s", trigger, table)); err != nil {
		return errors.Wrapf(err, "failed to drop the rename trigger on %s", table)
	}
	statement := fmt.Sprintf(
		"CREATE TRIGGER %s AFTER UPDATE OF name ON %s FOR EACH ROW EXECUTE PROCEDURE pgevents_notify_event()",
		trigger, table)
	if _, err := db.Exec(statement); err != nil {
		return errors.Wrapf(err, "failed to create the rename trigger on %s", table)
	}

	return nil
}

func (w *PgWatcher) OnAdd(cb Callback) {
	w.OnEvent(func(event *pgevents.TableEvent) {
		// we only emit the "add" event on an insert because wg-access-server
		// doesn't allow anyone to modify their public key or allowed IPs.
		// a future change to wg-access-server may require listening to "updates"
		// if either of those properties become mutable - and adding UPDATE back to
		// the trigger in NewPgWatcher.
		if event.Action == "INSERT" && !event.Truncated {
			w.emit(cb, event)
		}
	})
}

func (w *PgWatcher) OnUpdate(cb Callback) {
	w.OnEvent(func(event *pgevents.TableEvent) {
		// only the rename trigger reports updates, see attachRenameTrigger
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

	// A device row too large for a notification (8000 bytes - owner name and
	// email come unbounded from the identity provider) arrives without its
	// data, so there is nothing to add or remove directly. Every replica,
	// including the one that created the device, adds peers only from these
	// events, so ignoring it would leave the device without a peer anywhere.
	// Resynchronize instead, as after a reconnect that may have missed events.
	w.OnEvent(func(event *pgevents.TableEvent) {
		if event.Truncated {
			logrus.Warnf("received a %s event on %s without its row - it did not fit into a notification; resynchronizing devices", event.Action, event.Table)
			cb()
		}
	})
}

func (w *PgWatcher) emit(cb Callback, event *pgevents.TableEvent) {
	device := &Device{}
	if err := json.Unmarshal([]byte(event.Data), device); err != nil {
		logrus.Error(errors.Wrap(err, "failed to unmarshal postgres event data into device struct"))
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

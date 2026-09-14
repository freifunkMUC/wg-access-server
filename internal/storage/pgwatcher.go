package storage

import (
	"encoding/json"

	"github.com/freifunkMUC/pg-events/pkg/pgevents"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type PgWatcher struct {
	*pgevents.Listener
}

func NewPgWatcher(connectionString string, table string) (*PgWatcher, error) {
	logrus.Debug("creating postgres watcher")
	listener, err := pgevents.OpenListener(connectionString)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open pg listener")
	}

	// Only inserts and deletes are acted on (see OnAdd). Without UPDATE in the
	// trigger, the metadata sync - one UPDATE per active device every 30s on
	// every replica - no longer broadcasts each row to all replicas.
	if err := listener.AttachActions(table, pgevents.Insert, pgevents.Delete); err != nil {
		return nil, errors.Wrapf(err, "failed to attach listener to table: %s", table)
	}

	return &PgWatcher{
		Listener: listener,
	}, nil
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

func (w *PgWatcher) EmitDelete(device *Device) {
	// noop because we rely on postgres channels
}

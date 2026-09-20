package storage

import (
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// silentSetting marks a statement whose changes the storage reports itself,
// once they are durable.
const silentSetting = "wg-access-server:silent"

// GormWatcher turns the inserts and deletes gorm performs into storage
// events. The SQL backends that have no notification channel of their own -
// SQLite and MySQL - are served by exactly one process, so hooking into gorm
// is enough to learn about every change.
type GormWatcher struct {
	db    *gorm.DB
	table string

	// update and delete callbacks the storage invokes itself: a metadata
	// write is an UPDATE like any other and must stay silent (see
	// SQLStorage.Rename), and the deletes of a transaction may only be
	// reported once it has committed (see SQLStorage.DeleteForOwner).
	update []Callback
	delete []Callback

	// mu guards registered, which only makes the callback names unique
	mu         sync.Mutex
	registered int
}

func NewGormWatcher(db *gorm.DB, table string) *GormWatcher {
	logrus.Debug("creating gorm watcher")
	return &GormWatcher{db: db, table: table}
}

// name returns a callback name nobody else uses: registering the same name
// twice replaces the first callback, and several callers register here.
func (w *GormWatcher) name(kind string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.registered++
	return fmt.Sprintf("wg-access-server:%s:%d", kind, w.registered)
}

func (w *GormWatcher) OnAdd(cb Callback) {
	name := w.name("add")
	logrus.Debugf("registering gorm create callback %s", name)
	if err := w.db.Callback().Create().After("gorm:create").Register(name, func(tx *gorm.DB) {
		w.emit(cb, tx)
	}); err != nil {
		logrus.Error(err)
	}
}

func (w *GormWatcher) OnDelete(cb Callback) {
	w.mu.Lock()
	w.delete = append(w.delete, cb)
	w.mu.Unlock()

	name := w.name("delete")
	logrus.Debugf("registering gorm delete callback %s", name)
	if err := w.db.Callback().Delete().After("gorm:delete").Register(name, func(tx *gorm.DB) {
		w.emit(cb, tx)
	}); err != nil {
		logrus.Error(err)
	}
}

func (w *GormWatcher) OnUpdate(cb Callback) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.update = append(w.update, cb)
}

func (w *GormWatcher) OnReconnect(cb func()) {
	// noop because the watcher can't reconnect
}

func (w *GormWatcher) emit(cb Callback, tx *gorm.DB) {
	if _, silent := tx.Get(silentSetting); silent {
		// part of a transaction that reports its changes once it committed
		return
	}
	if tx.Error != nil {
		// the operation failed (e.g. constraint violation or rollback),
		// so we must not emit an event for a change that never happened
		return
	}
	if tx.Statement == nil || tx.Statement.Table != w.table {
		return
	}
	if device, ok := deviceOf(tx.Statement.Dest); ok {
		cb(device)
	}
}

// deviceOf digs the device out of what the statement was given. A bulk
// update or delete carries something else entirely - a model without values,
// or a slice - and there is no single device to report then.
func deviceOf(dest interface{}) (*Device, bool) {
	switch value := dest.(type) {
	case *Device:
		return value, true
	case **Device:
		return *value, true
	}
	return nil, false
}

func (w *GormWatcher) EmitAdd(device *Device) {
	// noop because we rely on gorm callback
}

func (w *GormWatcher) EmitUpdate(device *Device) {
	for _, cb := range w.callbacks(&w.update) {
		cb(device)
	}
}

func (w *GormWatcher) EmitDelete(device *Device) {
	for _, cb := range w.callbacks(&w.delete) {
		cb(device)
	}
}

// callbacks copies a callback list so it can be run without holding the lock.
func (w *GormWatcher) callbacks(list *[]Callback) []Callback {
	w.mu.Lock()
	defer w.mu.Unlock()
	callbacks := make([]Callback, len(*list))
	copy(callbacks, *list)
	return callbacks
}

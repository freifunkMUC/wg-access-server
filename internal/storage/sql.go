package storage

import (
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// migrationFailed explains the failure an operator is most likely to hit:
// the unique index on public_key cannot be created while the table still
// holds devices that share one.
const migrationFailed = `failed to migrate the database schema.

If this is about the unique index on public_key, the table holds devices
sharing a public key. Two devices with the same key cannot both work - the
WireGuard peer is identified by it - so find them:

    SELECT public_key, COUNT(*) FROM devices GROUP BY public_key HAVING COUNT(*) > 1;

and delete all but one device per key, then start the server again`

// gormLogWriter hands what gorm wants to log to logrus, at debug level: the
// statements are useful when chasing a problem and noise otherwise.
type gormLogWriter struct{}

func (gormLogWriter) Printf(format string, args ...interface{}) {
	logrus.WithField("module", "gorm").Debugf(format, args...)
}

func newGormLogger() gormlogger.Interface {
	return gormlogger.New(gormLogWriter{}, gormlogger.Config{
		SlowThreshold: 200 * time.Millisecond,
		// Info makes gorm report every statement; the writer above decides
		// that they are debug output.
		LogLevel: gormlogger.Info,
		// a device that does not exist is an answer, not a failure
		IgnoreRecordNotFoundError: true,
		Colorful:                  false,
	})
}

// implements Storage interface
type SQLStorage struct {
	Watcher
	db               *gorm.DB
	sqlType          string
	connectionString string
	allocationMu     sync.Mutex
}

func NewSqlStorage(u *url.URL) *SQLStorage {
	// a copy: the scheme is normalized below, and the caller's URL is theirs
	copied := *u
	u = &copied

	var connectionString string

	switch u.Scheme {
	case "postgresql":
		// handle `postgresql` as the scheme to be compatible with
		// standard uri style postgresql connection strings (i.e. like psql)
		u.Scheme = "postgres"
		fallthrough
	case "postgres":
		connectionString = pgconn(u)
	case "mysql":
		connectionString = mysqlconn(u)
	case "sqlite3":
		connectionString = sqlite3conn(u)
	default:
		// unreachable because our storage backend factory
		// function (contracts.go) already checks the url scheme.
		logrus.Panicf("unknown sql storage backend %s", u.Scheme)
	}

	return &SQLStorage{
		Watcher:          nil,
		db:               nil,
		sqlType:          u.Scheme,
		connectionString: connectionString,
	}
}

func pgconn(u *url.URL) string {
	password, _ := u.User.Password()
	decodedQuery, err := url.QueryUnescape(u.RawQuery)
	if err != nil {
		logrus.Warnf("failed to unescape connection string query parameters - they will be ignored")
		decodedQuery = ""
	}
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s %s",
		u.Hostname(),
		u.Port(),
		u.User.Username(),
		password,
		strings.TrimLeft(u.Path, "/"),
		decodedQuery,
	)
}

func mysqlconn(u *url.URL) string {
	password, _ := u.User.Password()

	// The devices table has time columns, and go-sql-driver/mysql only scans
	// them into time.Time with parseTime=true (default false). Without it every
	// device read fails, so require it instead of relying on the connection
	// string to mention it.
	query := u.Query()
	if value := query.Get("parseTime"); value != "true" {
		if value != "" {
			logrus.Warnf("mysql: overriding parseTime=%s with parseTime=true, which wg-access-server needs to read devices", value)
		}
		query.Set("parseTime", "true")
	}

	return fmt.Sprintf(
		"%s:%s@tcp(%s)/%s?%s",
		u.User.Username(),
		password,
		u.Host,
		strings.TrimLeft(u.Path, "/"),
		query.Encode(),
	)
}

func sqlite3conn(u *url.URL) string {
	return filepath.Join(u.Host, u.Path)
}

// dialector picks the driver for the configured backend.
func (s *SQLStorage) dialector() (gorm.Dialector, error) {
	switch s.sqlType {
	case "postgres":
		return postgres.Open(s.connectionString), nil
	case "mysql":
		return mysql.New(mysql.Config{
			DSN: s.connectionString,
			// Without a default size a string column becomes longtext, which
			// cannot carry the unique index on public_key. varchar(255) is
			// also what the schema has held since the beginning.
			DefaultStringSize: 255,
			// The driver would otherwise migrate every datetime column of
			// existing installations to datetime(3).
			DisableDatetimePrecision: true,
		}), nil
	case "sqlite3":
		return sqlite.Open(s.connectionString), nil
	}
	return nil, errors.Errorf("unknown sql storage backend %s", s.sqlType)
}

func (s *SQLStorage) Open() error {
	dialector, err := s.dialector()
	if err != nil {
		return err
	}

	db, err := gorm.Open(dialector, &gorm.Config{Logger: newGormLogger()})
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to connect to %s", s.sqlType))
	}
	s.db = db

	// Migrate the schema. The error matters: a failed migration used to be
	// swallowed here, which is how MySQL ended up without the unique index
	// on public_key for years.
	if err := s.db.AutoMigrate(&Device{}); err != nil {
		return errors.Wrap(err, migrationFailed)
	}
	if err := s.db.AutoMigrate(&APIToken{}); err != nil {
		return errors.Wrap(err, "failed to migrate the api tokens table")
	}

	table, err := deviceTable(db)
	if err != nil {
		return err
	}

	sqlDB, err := s.sqlDB()
	if err != nil {
		return err
	}

	switch s.sqlType {
	case "postgres":
		watcher, err := NewPgWatcher(sqlDB, s.connectionString, table)
		if err != nil {
			return errors.Wrap(err, "failed to create pg watcher")
		}
		s.Watcher = watcher
	case "mysql":
		fallthrough
	case "sqlite3":
		s.Watcher = NewGormWatcher(db, table)
	default:
		s.Watcher = NewInProcessWatcher()
	}

	return nil
}

// deviceTable returns the table name gorm uses for a Device.
func deviceTable(db *gorm.DB) (string, error) {
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(&Device{}); err != nil {
		return "", errors.Wrap(err, "failed to determine the devices table name")
	}
	return stmt.Schema.Table, nil
}

// sqlDB returns the underlying database handle, for the things gorm does not
// do itself: pinging and the session-level allocation lock.
func (s *SQLStorage) sqlDB() (*sql.DB, error) {
	if s.db == nil {
		return nil, errors.New("storage is not open")
	}
	return s.db.DB()
}

func (s *SQLStorage) Close() error {
	if s.db == nil {
		return nil
	}
	db, err := s.sqlDB()
	if err != nil {
		return err
	}
	return db.Close()
}

func (s *SQLStorage) Save(device *Device) error {
	logrus.Debugf("saving device %s", key(device))

	// Deliberately not gorm's Save: that one falls back to
	// "INSERT ... ON CONFLICT UPDATE ALL", which on MySQL becomes
	// "INSERT ... ON DUPLICATE KEY UPDATE" - a statement that does not care
	// which unique index was violated. A device carrying another device's
	// public key would then overwrite that other device's row instead of
	// being refused, which is exactly what the unique index is there to
	// prevent. Looking first and then inserting or updating keeps a
	// violation a violation on every backend.
	var existing int64
	if err := s.db.Model(&Device{}).
		Where("owner = ? AND name = ?", device.Owner, device.Name).
		Count(&existing).Error; err != nil {
		return errors.Wrap(err, "failed to look up the device")
	}

	if existing == 0 {
		if err := s.db.Create(device).Error; err != nil {
			return errors.Wrap(err, "failed to write device")
		}
		s.EmitAdd(device)
		return nil
	}

	// Select("*") so that zeroed fields are written too - clearing the
	// endpoint of a device that went away has to stick.
	if err := s.db.Model(device).Select("*").Updates(device).Error; err != nil {
		return errors.Wrap(err, "failed to write device")
	}
	s.EmitAdd(device)
	return nil
}

func (s *SQLStorage) RecordMetadata(updates []MetadataUpdate) error {
	if len(updates) == 0 {
		return nil
	}

	// One transaction per sync, so a deployment with many peers commits once
	// instead of once per device.
	tx := s.db.Begin()
	if tx.Error != nil {
		return errors.Wrap(tx.Error, "failed to begin metadata transaction")
	}

	for _, update := range updates {
		columns := map[string]interface{}{}
		// Add in the database rather than read-modify-write in Go: concurrent
		// replicas then cannot lose each other's traffic. COALESCE because
		// rows written by old versions may hold NULL, and NULL + n is NULL.
		if update.ReceiveBytes != 0 {
			columns["receive_bytes"] = gorm.Expr("COALESCE(receive_bytes, 0) + ?", update.ReceiveBytes)
		}
		if update.TransmitBytes != 0 {
			columns["transmit_bytes"] = gorm.Expr("COALESCE(transmit_bytes, 0) + ?", update.TransmitBytes)
		}
		if update.Connection != nil {
			columns["endpoint"] = update.Connection.Endpoint
			columns["last_handshake_time"] = update.Connection.LastHandshakeTime
		}
		if len(columns) == 0 {
			continue
		}

		// An explicit UPDATE, never Save: in gorm v1 Save falls back to an
		// INSERT when nothing matches, which would re-create (and re-add as a
		// WireGuard peer) a device deleted while this sync was running.
		// UpdateColumns also skips hooks, so no watcher event fires.
		q := tx.Model(&Device{}).Where("public_key = ?", update.PublicKey).UpdateColumns(columns)
		if q.Error != nil {
			tx.Rollback()
			return errors.Wrap(q.Error, "failed to record device metadata")
		}
		if q.RowsAffected == 0 {
			logrus.Debugf("device with public key %s no longer exists - skipped metadata update", update.PublicKey)
		}
	}

	if err := tx.Commit().Error; err != nil {
		return errors.Wrap(err, "failed to commit device metadata")
	}
	return nil
}

func (s *SQLStorage) Rename(device *Device, newName string) (*Device, error) {
	logrus.Debugf("renaming device %s to %s", key(device), newName)

	// Owner and name together are the primary key, so both identify the row.
	// An UpdateColumn (no hooks) keeps this out of the gorm watcher, which
	// expects the value of a create or delete and cannot map a bulk update
	// back to a device.
	q := s.db.Model(&Device{}).Where("owner = ? AND name = ?", device.Owner, device.Name).UpdateColumn("name", newName)
	if q.Error != nil {
		return nil, errors.Wrap(q.Error, "failed to rename device")
	}
	if q.RowsAffected == 0 {
		return nil, errors.Errorf("device '%s' of user '%s' no longer exists", device.Name, device.Owner)
	}

	renamed := *device
	renamed.Name = newName

	// Postgres learns about this from its own trigger, so that every replica
	// hears about it; the other backends are single-instance and are told
	// here (EmitUpdate is a no-op for the pg watcher).
	s.EmitUpdate(&renamed)

	return &renamed, nil
}

func (s *SQLStorage) List(username string) ([]*Device, error) {
	var err error
	devices := []*Device{}
	if username != "" {
		err = s.db.Where("owner = ?", username).Find(&devices).Error
	} else {
		err = s.db.Find(&devices).Error
	}

	logrus.Debugf("found %d device(s)", len(devices))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read devices from sql")
	}
	return devices, nil
}

func (s *SQLStorage) Get(owner string, name string) (*Device, error) {
	device := &Device{}
	if err := s.db.Where("owner = ? AND name = ?", owner, name).First(&device).Error; err != nil {
		return nil, errors.Wrapf(err, "failed to read device")
	}
	return device, nil
}

func (s *SQLStorage) GetByPublicKey(publicKey string) (*Device, error) {
	device := &Device{}
	if err := s.db.Where("public_key = ?", publicKey).First(&device).Error; err != nil {
		return nil, errors.Wrapf(err, "failed to read device")
	}
	return device, nil
}

func (s *SQLStorage) Delete(device *Device) error {
	if err := s.db.Delete(device).Error; err != nil {
		return errors.Wrap(err, "failed to delete device file")
	}
	s.EmitDelete(device)
	return nil
}

// DeleteForOwner removes every device of one user in a single transaction.
// The events follow the commit: reporting a device as gone and then rolling
// the delete back would leave the WireGuard peers and the DNS zone describing
// a state the database never reached.
func (s *SQLStorage) DeleteForOwner(owner string) ([]*Device, error) {
	var deleted []*Device

	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("owner = ?", owner).Find(&deleted).Error; err != nil {
			return errors.Wrap(err, "failed to list the devices of the user")
		}

		// One statement per device, not a bulk delete: the watcher reports
		// devices, and a bulk delete carries no row to report. Silent,
		// because these are reported below - after the commit.
		//
		// The chain starts at tx every time. Hoisting the Set out of the
		// loop would reuse one statement, and gorm would keep adding each
		// device's primary key to the same WHERE until it matches nothing.
		for _, device := range deleted {
			if err := tx.Set(silentSetting, true).Delete(device).Error; err != nil {
				return errors.Wrapf(err, "failed to delete device '%s'", device.Name)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	for _, device := range deleted {
		s.EmitDelete(device)
	}

	return deleted, nil
}

func (s *SQLStorage) Ping() error {
	db, err := s.sqlDB()
	if err != nil {
		return errors.Wrap(err, "failed to get db")
	}

	if err := db.Ping(); err != nil {
		return errors.Wrap(err, "failed to ping db")
	}
	return nil
}

package storage

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// GormLogger is a custom logger for Gorm, making it use logrus.
type GormLogger struct{}

// Print handles log events from Gorm for the custom logger.
func (*GormLogger) Print(v ...interface{}) {
	switch v[0] {
	case "sql":
		logrus.WithFields(
			logrus.Fields{
				"module":  "gorm",
				"type":    "sql",
				"rows":    v[5],
				"src_ref": v[1],
				"values":  v[4],
			},
		).Debug(v[3])
	case "logrus":
		logrus.WithFields(logrus.Fields{"module": "gorm", "type": "logrus"}).Print(v[2])
	}
}

// implements Storage interface
type SQLStorage struct {
	Watcher
	db               *gorm.DB
	sqlType          string
	connectionString string
}

func NewSqlStorage(u *url.URL) *SQLStorage {
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

func (s *SQLStorage) Open() error {
	db, err := gorm.Open(s.sqlType, s.connectionString)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to connect to %s", s.sqlType))
	}
	s.db = db

	db.SetLogger(&GormLogger{})
	db.LogMode(true)

	// Migrate the schema
	s.db.AutoMigrate(&Device{})

	switch s.sqlType {
	case "postgres":
		watcher, err := NewPgWatcher(s.connectionString, db.NewScope(&Device{}).TableName())
		if err != nil {
			return errors.Wrap(err, "failed to create pg watcher")
		}
		s.Watcher = watcher
	case "mysql":
		fallthrough
	case "sqlite3":
		s.Watcher = NewGormWatcher(db, db.NewScope(&Device{}).TableName())
	default:
		s.Watcher = NewInProcessWatcher()
	}

	return nil
}

func (s *SQLStorage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *SQLStorage) Save(device *Device) error {
	logrus.Debugf("saving device %s", key(device))
	if err := s.db.Save(&device).Error; err != nil {
		return errors.Wrapf(err, "failed to write device")
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
	if err := s.db.Delete(&device).Error; err != nil {
		return errors.Wrap(err, "failed to delete device file")
	}
	s.EmitDelete(device)
	return nil
}

func (s *SQLStorage) Ping() error {
	db := s.db.DB()
	if db == nil {
		return errors.New("failed to get db")
	}

	if err := db.Ping(); err != nil {
		return errors.Wrap(err, "failed to ping db")
	}
	return nil
}

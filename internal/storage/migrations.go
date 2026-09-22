package storage

import (
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// Schema changes are migrations: each one runs once per database, in order,
// and is recorded in the schema_migrations table.
//
// A migration never changes once released - it describes what the schema
// looked like at the time, so it works on its own copies of the models
// rather than the ones in use today. To change the schema, append a
// migration. TestMigrationsMatchTheModels fails if the models and the
// migrations disagree.
var migrations = []migration{
	{
		// The schema as it was before migrations existed. AutoMigrate, as the
		// server used to run on every start: it creates the table on a new
		// database and brings the one of an older version up to date,
		// including the unique index on public_key that older MySQL
		// installations lack.
		id: "0001_devices",
		apply: func(db *gorm.DB) error {
			if err := db.AutoMigrate(&deviceV1{}); err != nil {
				return errors.Wrap(err, migrationFailed)
			}
			return nil
		},
	},
	{
		id: "0002_api_tokens",
		apply: func(db *gorm.DB) error {
			return db.AutoMigrate(&apiTokenV1{})
		},
	},
}

type migration struct {
	id    string
	apply func(db *gorm.DB) error
}

// schemaLockName serializes schema changes across the replicas sharing a
// database, so that two of them starting at once do not both alter the same
// table. A var so tests can use their own lock.
var schemaLockName = "wg-access-server/schema"

// schemaLockTimeout is how long a replica waits for another one to finish
// migrating. Migrating a large table can take a while.
var schemaLockTimeout = 10 * time.Minute

type schemaMigration struct {
	ID        string `gorm:"type:varchar(100);primaryKey"`
	AppliedAt time.Time
}

func (schemaMigration) TableName() string {
	return "schema_migrations"
}

func (s *SQLStorage) withSchemaLock(fn func() error) error {
	return s.withDatabaseLock(schemaLockName, "schema lock", schemaLockTimeout, fn)
}

func runMigrations(db *gorm.DB, migrations []migration) error {
	if err := db.AutoMigrate(&schemaMigration{}); err != nil {
		return errors.Wrap(err, "failed to create the schema_migrations table")
	}

	var applied []schemaMigration
	if err := db.Find(&applied).Error; err != nil {
		return errors.Wrap(err, "failed to read the applied migrations")
	}

	known := make(map[string]bool, len(migrations))
	for _, m := range migrations {
		known[m.id] = true
	}
	done := make(map[string]bool, len(applied))
	var unknown []string
	for _, a := range applied {
		done[a.ID] = true
		if !known[a.ID] {
			unknown = append(unknown, a.ID)
		}
	}

	// A newer version has changed the schema in ways this one knows nothing
	// about. Running on it could mean writing rows that no longer fit.
	if len(unknown) > 0 {
		return errors.Errorf("the database was migrated by a newer version of wg-access-server (unknown migrations: %s). "+
			"Run that version or newer, or restore a backup taken before the upgrade", strings.Join(unknown, ", "))
	}

	for _, m := range migrations {
		if done[m.id] {
			continue
		}
		logrus.Infof("Applying database migration %s", m.id)
		// On MySQL, schema changes commit implicitly, so a failure can leave
		// a migration half applied there. Each one is written so that running
		// it again completes it.
		err := db.Transaction(func(tx *gorm.DB) error {
			if err := m.apply(tx); err != nil {
				return err
			}
			return tx.Create(&schemaMigration{ID: m.id, AppliedAt: time.Now()}).Error
		})
		if err != nil {
			return errors.Wrapf(err, "database migration %s failed", m.id)
		}
	}

	return nil
}

// deviceV1 is the devices table as 0001_devices created it.
type deviceV1 struct {
	Owner             string `gorm:"type:varchar(100);primaryKey"`
	OwnerName         string
	OwnerEmail        string
	OwnerProvider     string
	Name              string `gorm:"type:varchar(100);primaryKey"`
	PublicKey         string `gorm:"uniqueIndex:uix_devices_public_key"`
	PresharedKey      string `gorm:"type:varchar(100)"`
	Address           string
	CreatedAt         time.Time `gorm:"column:created_at"`
	LastHandshakeTime *time.Time
	ReceiveBytes      int64
	TransmitBytes     int64
	Endpoint          string
}

func (deviceV1) TableName() string {
	return "devices"
}

// apiTokenV1 is the api_tokens table as 0002_api_tokens created it.
type apiTokenV1 struct {
	ID         string `gorm:"type:varchar(32);primaryKey"`
	Owner      string `gorm:"type:varchar(100);index:idx_api_tokens_owner"`
	Name       string `gorm:"type:varchar(100)"`
	Hash       string `gorm:"type:varchar(64);uniqueIndex:uix_api_tokens_hash"`
	Identity   string `gorm:"type:text"`
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
}

func (apiTokenV1) TableName() string {
	return "api_tokens"
}

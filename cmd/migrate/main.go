package migrate

import (
	"errors"
	"fmt"

	"github.com/freifunkMUC/wg-access-server/internal/storage"

	"github.com/alecthomas/kingpin/v2"
	"github.com/sirupsen/logrus"
)

func Register(app *kingpin.Application) *migratecmd {
	cmd := &migratecmd{}
	cli := app.Command(cmd.Name(), "Migrate your wg-access-server devices between storage backends. This tool is provided on a best effort bases.")
	cli.Arg("source", "The source storage URI").Required().StringVar(&cmd.src)
	cli.Arg("destination", "The destination storage URI").Required().StringVar(&cmd.dest)
	return cmd
}

type migratecmd struct {
	src  string
	dest string
}

func (cmd *migratecmd) Name() string {
	return "migrate"
}

func (cmd *migratecmd) Run() {
	srcBackend, err := open(cmd.src, "src")
	if err != nil {
		logrus.Fatal(err)
	}
	defer srcBackend.Close()

	destBackend, err := open(cmd.dest, "destination")
	if err != nil {
		logrus.Fatal(err)
	}
	defer destBackend.Close()

	if err := copyAll(srcBackend, destBackend); err != nil {
		logrus.Fatal(err)
	}
}

func open(uri, what string) (storage.Storage, error) {
	backend, err := storage.NewStorage(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s storage backend: %w", what, err)
	}
	if err := backend.Open(); err != nil {
		return nil, fmt.Errorf("failed to connect/open %s storage backend: %w", what, err)
	}
	return backend, nil
}

// copyAll writes everything the source holds to the destination: the devices,
// the API tokens that act for their owners, and the users with what they set
// for themselves. A token left behind would stop working the moment the server
// is pointed at the new backend, without anything saying so - and a user left
// behind would lose their own password and their second factor, and sign in
// with the configured password alone.
func copyAll(src, dest storage.Storage) error {
	if err := copyUsers(src, dest); err != nil {
		return err
	}

	devices, err := src.List("")
	if err != nil {
		return fmt.Errorf("failed to list all devices from source storage backend: %w", err)
	}
	tokens, err := src.ListTokens("")
	if err != nil {
		return fmt.Errorf("failed to list all api tokens from source storage backend: %w", err)
	}

	logrus.Infof("copying %v devices and %v api tokens from source --> destination backend", len(devices), len(tokens))

	for _, device := range devices {
		if err := dest.Save(device); err != nil {
			return fmt.Errorf("failed to write device to destination storage backend: %w", err)
		}
	}
	for _, token := range tokens {
		if err := dest.SaveToken(token); err != nil {
			return fmt.Errorf("failed to write api token to destination storage backend: %w", err)
		}
	}
	return nil
}

// copyUsers writes the users, their own passwords, their second factors and
// their passkeys. Running it again leaves what it already copied as it is.
func copyUsers(src, dest storage.Storage) error {
	users, err := src.Users()
	if err != nil {
		return fmt.Errorf("failed to list all users from source storage backend: %w", err)
	}

	passkeys := 0
	for _, user := range users {
		if err := dest.SaveUser(user); err != nil {
			return fmt.Errorf("failed to write user to destination storage backend: %w", err)
		}
		// SaveUser is what a login calls, and leaves these alone for a user
		// who is already there
		if err := dest.SetUserPassword(user.Subject, user.PasswordHash, user.PasswordFrom); err != nil {
			return fmt.Errorf("failed to write the password of a user to destination storage backend: %w", err)
		}
		if err := dest.SetUserTOTP(user.Subject, user.TOTP()); err != nil {
			return fmt.Errorf("failed to write the second factor of a user to destination storage backend: %w", err)
		}

		owned, err := src.ListPasskeys(user.Subject)
		if err != nil {
			return fmt.Errorf("failed to list the passkeys of a user from source storage backend: %w", err)
		}
		for _, passkey := range owned {
			if err := dest.AddPasskey(passkey); err != nil && !errors.Is(err, storage.ErrPasskeyExists) {
				return fmt.Errorf("failed to write a passkey to destination storage backend: %w", err)
			}
		}
		passkeys += len(owned)
	}

	logrus.Infof("copied %v users and %v passkeys from source --> destination backend", len(users), passkeys)
	return nil
}

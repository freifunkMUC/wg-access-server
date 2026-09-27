package migrate

import (
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
// and the API tokens that act for their owners. A token left behind would
// stop working the moment the server is pointed at the new backend, without
// anything saying so.
func copyAll(src, dest storage.Storage) error {
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

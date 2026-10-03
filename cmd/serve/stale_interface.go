package serve

import (
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// removeStaleInterface deletes the interface called name if it exists. One found
// at startup is left over from a run that did not clean up; creating it again
// would fail with "file exists".
func removeStaleInterface(
	name string,
	linkByName func(string) (netlink.Link, error),
	linkDel func(netlink.Link) error,
) error {
	link, err := linkByName(name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("failed to look up interface %s: %w", name, err)
	}

	logrus.Warnf("removing stale interface %s left over from a previous run", name)
	if err := linkDel(link); err != nil {
		return fmt.Errorf("failed to remove stale interface %s: %w", name, err)
	}
	return nil
}

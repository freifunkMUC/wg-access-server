package serve

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestRemoveStaleInterfaceDeletesExistingLink(t *testing.T) {
	var deleted []string
	err := removeStaleInterface("wg0",
		func(name string) (netlink.Link, error) { return testLink(name), nil },
		func(l netlink.Link) error { deleted = append(deleted, l.Attrs().Name); return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deleted) != 1 || deleted[0] != "wg0" {
		t.Fatalf("deleted %v, want [wg0]", deleted)
	}
}

func TestRemoveStaleInterfaceNothingToRemove(t *testing.T) {
	err := removeStaleInterface("wg0",
		func(string) (netlink.Link, error) { return nil, netlink.LinkNotFoundError{} },
		func(netlink.Link) error { t.Fatal("must not delete anything"); return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRemoveStaleInterfaceLookupFailure(t *testing.T) {
	boom := errors.New("boom")
	err := removeStaleInterface("wg0",
		func(string) (netlink.Link, error) { return nil, boom },
		func(netlink.Link) error { t.Fatal("must not delete anything"); return nil },
	)
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want it to wrap %v", err, boom)
	}
}

func TestRemoveStaleInterfaceDeleteFailure(t *testing.T) {
	boom := errors.New("boom")
	err := removeStaleInterface("wg0",
		func(name string) (netlink.Link, error) { return testLink(name), nil },
		func(netlink.Link) error { return boom },
	)
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want it to wrap %v", err, boom)
	}
}

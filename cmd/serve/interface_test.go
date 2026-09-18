package serve

import (
	"errors"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func testLink(name string) netlink.Link {
	return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

func defaultRoute(cidr string) netlink.Route {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return netlink.Route{Dst: dst}
}

func TestDefaultInterfaceName(t *testing.T) {
	var queried []int
	routes := map[string]map[int][]netlink.Route{
		"eth0": {
			netlink.FAMILY_V4: {defaultRoute("192.0.2.0/24")},
			netlink.FAMILY_V6: {defaultRoute("2001:db8::/32")},
		},
		"eth1": {
			netlink.FAMILY_V4: {defaultRoute("198.51.100.0/24")},
			netlink.FAMILY_V6: {defaultRoute("::/0")},
		},
	}
	routeList := func(link netlink.Link, family int) ([]netlink.Route, error) {
		queried = append(queried, family)
		return routes[link.Attrs().Name][family], nil
	}

	// eth1 carries the default route, and only in the IPv6 table - a run that
	// asks for the wrong address families would miss it.
	name := defaultInterfaceName([]netlink.Link{testLink("eth0"), testLink("eth1")}, routeList)
	if name != "eth1" {
		t.Errorf("got interface %q, want eth1", name)
	}
	for _, family := range queried {
		if family != netlink.FAMILY_V4 && family != netlink.FAMILY_V6 {
			t.Errorf("routes were listed for address family %d, want only %d (IPv4) and %d (IPv6)",
				family, netlink.FAMILY_V4, netlink.FAMILY_V6)
		}
	}
}

func TestDefaultInterfaceNameSkipsFailingLink(t *testing.T) {
	routeList := func(link netlink.Link, family int) ([]netlink.Route, error) {
		if link.Attrs().Name == "broken" {
			return nil, errors.New("interface went away")
		}
		if family == netlink.FAMILY_V4 {
			return []netlink.Route{defaultRoute("0.0.0.0/0")}, nil
		}
		return nil, nil
	}

	name := defaultInterfaceName([]netlink.Link{testLink("broken"), testLink("eth0")}, routeList)
	if name != "eth0" {
		t.Errorf("got interface %q, want eth0: an unreadable interface must not stop the search", name)
	}
}

func TestDefaultInterfaceNameWithoutDefaultRoute(t *testing.T) {
	routeList := func(link netlink.Link, family int) ([]netlink.Route, error) {
		return []netlink.Route{defaultRoute("192.0.2.0/24")}, nil
	}

	if name := defaultInterfaceName([]netlink.Link{testLink("eth0")}, routeList); name != "" {
		t.Errorf("got interface %q, want an empty name", name)
	}
}

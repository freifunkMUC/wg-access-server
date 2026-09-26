package network

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// nftTable holds every rule wg-access-server sets up with nftables. It is
// one table for IPv4 and IPv6 ("inet"), owned by wg-access-server alone, so
// it can be replaced as a whole without touching anybody else's rules.
const nftTable = "wg_access_server"

// interfaceName is what Linux accepts as an interface name. The name goes
// into the ruleset as text, so it must not be able to end the string.
var interfaceName = regexp.MustCompile(`^[A-Za-z0-9_.@:-]{1,15}$`)

// nftablesRuleset returns the ruleset for options: the same rules the
// iptables backend sets up, in the same order. It starts by declaring and
// deleting the table, so that applying it replaces whatever an earlier start
// left behind - in one transaction, with no moment without rules.
func nftablesRuleset(options ForwardingOptions) (string, error) {
	if options.GatewayIface != "" && !interfaceName.MatchString(options.GatewayIface) {
		return "", errors.Errorf("invalid gateway interface name %q", options.GatewayIface)
	}

	var forward, postrouting []string
	for _, f := range options.families() {
		prefix, err := netip.ParsePrefix(f.cidr)
		if err != nil {
			return "", errors.Wrapf(err, "invalid VPN network %q", f.cidr)
		}
		cidr := prefix.Masked().String()
		ip := f.keyword

		if options.ClientIsolation {
			// reject traffic between devices
			forward = append(forward, fmt.Sprintf("%s saddr %s %s daddr %s reject", ip, cidr, ip, cidr))
		}
		// accept client traffic to the allowed networks
		for _, network := range f.allowed {
			forward = append(forward, fmt.Sprintf("%s saddr %s %s daddr %s accept", ip, cidr, ip, network))
		}
		// without NAT, the answers come back to the clients' own addresses
		if !f.nat {
			for _, network := range f.allowed {
				forward = append(forward, fmt.Sprintf("%s saddr %s %s daddr %s accept", ip, network, ip, cidr))
			}
		}
		// and reject everything else the clients send
		forward = append(forward, fmt.Sprintf("%s saddr %s reject", ip, cidr))

		if options.GatewayIface != "" && f.nat {
			postrouting = append(postrouting, fmt.Sprintf("%s saddr %s oifname %q masquerade", ip, cidr, options.GatewayIface))
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\n", nftTable)
	fmt.Fprintf(&b, "delete table inet %s\n", nftTable)
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n")
	for _, rule := range forward {
		fmt.Fprintf(&b, "\t\t%s\n", rule)
	}
	b.WriteString("\t}\n\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	for _, rule := range postrouting {
		fmt.Fprintf(&b, "\t\t%s\n", rule)
	}
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}

func configureNftables(options ForwardingOptions) error {
	ruleset, err := nftablesRuleset(options)
	if err != nil {
		return err
	}
	logrus.Debugf("applying the nftables ruleset:\n%s", ruleset)
	return runNft(ruleset)
}

// runNft applies a ruleset as one transaction: all of it, or none.
func runNft(ruleset string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "failed to apply the nftables rules: %s", strings.TrimSpace(output.String()))
	}
	return nil
}

// removeNftables drops the table a start with the nftables backend left
// behind. Best effort: without the nft binary there is nothing to remove.
func removeNftables() {
	if _, err := exec.LookPath("nft"); err != nil {
		return
	}
	ruleset := fmt.Sprintf("table inet %s\ndelete table inet %s\n", nftTable, nftTable)
	if err := runNft(ruleset); err != nil {
		logrus.Warn(errors.Wrap(err, "failed to remove the nftables rules of an earlier start"))
	}
}

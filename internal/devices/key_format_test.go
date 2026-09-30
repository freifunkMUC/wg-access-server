package devices

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWireGuardKeyFormat(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !wgKeyRegex.MatchString(key.PublicKey().String()) {
		t.Errorf("a generated key was refused: %s", key.PublicKey())
	}

	// '|' is not base64: a key ending in it cannot be parsed, so the peer
	// could never be added
	broken := strings.Repeat("A", 42) + "|="
	if wgKeyRegex.MatchString(broken) {
		t.Errorf("%q was accepted", broken)
	}
	if _, err := wgtypes.ParseKey(broken); err == nil {
		t.Errorf("%q parses, the test is wrong", broken)
	}
}

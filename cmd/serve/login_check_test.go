package serve

import (
	"errors"
	"testing"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
)

// A device names its owner by the subject alone. Two providers that hand out
// the same subject would make two people one: whoever signs in second gets
// the devices of the first.
func TestCheckLogin(t *testing.T) {
	for _, tc := range []struct {
		name    string
		device  string // the provider of a device, none when empty
		legacy  bool   // a device from before devices named their provider
		signsIn string
		refused bool
	}{
		{name: "somebody new", signsIn: "keycloak"},
		{name: "a device of another identity provider", device: "keycloak", signsIn: "azure", refused: true},
		{name: "a device of the built-in sign-in", device: "simple", signsIn: "keycloak", refused: true},
		{name: "a device of an identity provider", device: "keycloak", signsIn: "simple", refused: true},
		{name: "a device of the same provider", device: "keycloak", signsIn: "keycloak"},
		// both check the users the configuration lists
		{name: "a device of the other built-in sign-in", device: "basic", signsIn: "simple"},
		{name: "a device that names no provider", legacy: true, signsIn: "keycloak"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := storage.NewMemoryStorage()
			if tc.device != "" || tc.legacy {
				if err := s.Save(&storage.Device{
					Owner: "alice", OwnerProvider: tc.device, Name: "laptop",
					PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Address: "10.44.0.2/32",
				}); err != nil {
					t.Fatal(err)
				}
			}

			err := checkLogin(s)(&authsession.Identity{Subject: "alice", Provider: tc.signsIn})

			var refused *authruntime.RefusedError
			if tc.refused && !errors.As(err, &refused) {
				t.Errorf("check = %v, want the sign-in refused", err)
			}
			if !tc.refused && err != nil {
				t.Errorf("check = %v, want the sign-in let through", err)
			}
		})
	}
}

// unreadableDevices is a database that cannot say whose devices there are.
type unreadableDevices struct {
	storage.Storage
}

func (unreadableDevices) List(string) ([]*storage.Device, error) {
	return nil, errors.New("connection refused")
}

// Not knowing whether the subject is somebody else's must not let the sign-in
// through.
func TestCheckLoginWithoutTheDevices(t *testing.T) {
	err := checkLogin(unreadableDevices{storage.NewMemoryStorage()})(&authsession.Identity{Subject: "alice", Provider: "keycloak"})
	if err == nil {
		t.Fatal("the sign-in went through without knowing whose devices there are")
	}
	var refused *authruntime.RefusedError
	if errors.As(err, &refused) {
		t.Errorf("check = %v, want a failure rather than a refusal", err)
	}
}

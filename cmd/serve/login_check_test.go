package serve

import (
	"errors"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// A device names its owner by the subject alone, and so do the users row, the
// policies and the DNS names. Two providers that hand out the same subject
// would make two people one: whoever signs in second gets the devices of the
// first.
func TestCheckLogin(t *testing.T) {
	for _, tc := range []struct {
		name    string
		user    string // the provider of the users row, none when empty
		device  string // the provider of a device, none when empty
		legacy  bool   // a device from before devices named their provider
		signsIn string
		refused bool
	}{
		{name: "somebody new", signsIn: "keycloak"},
		{name: "the same provider again", user: "keycloak", signsIn: "keycloak"},
		{name: "another identity provider", user: "keycloak", signsIn: "azure", refused: true},
		{name: "an identity provider after the built-in sign-in", user: "simple", signsIn: "keycloak", refused: true},
		{name: "the built-in sign-in after an identity provider", user: "keycloak", signsIn: "simple", refused: true},
		// both check the users the configuration lists
		{name: "basic after simple", user: "simple", signsIn: "basic"},
		{name: "simple after basic", user: "basic", signsIn: "simple"},
		// before the users were remembered, only the devices say who it was
		{name: "a device of another provider", device: "simple", signsIn: "keycloak", refused: true},
		{name: "a device of the same provider", device: "keycloak", signsIn: "keycloak"},
		{name: "a device of the other built-in sign-in", device: "basic", signsIn: "simple"},
		{name: "a device that names no provider", legacy: true, signsIn: "keycloak"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := storage.NewMemoryStorage()
			if tc.user != "" {
				if err := s.SaveUser(&storage.User{Subject: "alice", Provider: tc.user, LastLogin: time.Now()}); err != nil {
					t.Fatal(err)
				}
			}
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

// unreadableUsers is a database that cannot say who somebody is.
type unreadableUsers struct {
	storage.Storage
}

func (unreadableUsers) GetUser(string) (*storage.User, error) {
	return nil, errors.New("connection refused")
}

// Not knowing whether the subject is somebody else's must not let the sign-in
// through.
func TestCheckLoginWithoutTheUsers(t *testing.T) {
	err := checkLogin(unreadableUsers{storage.NewMemoryStorage()})(&authsession.Identity{Subject: "alice", Provider: "keycloak"})
	if err == nil {
		t.Fatal("the sign-in went through without knowing who alice is")
	}
	var refused *authruntime.RefusedError
	if errors.As(err, &refused) {
		t.Errorf("check = %v, want a failure rather than a refusal: nobody was found to be anybody", err)
	}
}

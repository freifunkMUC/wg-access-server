package serve

import (
	"fmt"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authconfig"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
)

// checkLogin refuses a sign-in whose subject is already somebody else's: a
// person whose devices were added through another provider. A device names
// its owner by the subject alone, so two providers handing out the same
// subject would make two people one - whoever signs in second would get the
// devices of the first. Basic and simple auth check the same configured
// users, so they count as one.
func checkLogin(storageBackend storage.Storage) func(*authsession.Identity) error {
	return func(identity *authsession.Identity) error {
		devices, err := storageBackend.List(identity.Subject)
		if err != nil {
			return fmt.Errorf("failed to read the devices of %q to check the sign-in: %w", identity.Subject, err)
		}
		for _, device := range devices {
			// a device from before devices named their provider says
			// nothing either way
			if device.OwnerProvider == "" || sameProvider(device.OwnerProvider, identity.Provider) {
				continue
			}
			return &authruntime.RefusedError{
				Reason: "This account already signs in another way here. Sign in the way you did before, or ask an admin.",
				Detail: fmt.Sprintf("the subject %q signed in through %q has devices of a user of %q", identity.Subject, identity.Provider, device.OwnerProvider),
			}
		}
		return nil
	}
}

func builtIn(provider string) bool {
	return provider == authconfig.BasicAuthProvider || provider == authconfig.SimpleAuthProvider
}

func sameProvider(a string, b string) bool {
	return a == b || (builtIn(a) && builtIn(b))
}

package authconfig

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authruntime"
)

// sessionNotStarted answers a sign-in the provider accepted but that did not
// become a session. A refusal is the person's business, and they are told
// why. Anything else is the server's: the details go to the log, not to the
// browser - and it is not reported as wrong credentials either, which would
// send people looking for the wrong thing.
func sessionNotStarted(w http.ResponseWriter, r *http.Request, err error, after string) {
	var refused *authruntime.RefusedError
	if errors.As(err, &refused) {
		logrus.Warnf("Refused a sign-in %s (remote address: %s): %s", after, r.RemoteAddr, refused)
		http.Error(w, refused.Reason, http.StatusForbidden)
		return
	}
	logrus.Error(fmt.Errorf("failed to start the session %s: %w", after, err))
	http.Error(w, "Could not sign in", http.StatusInternalServerError)
}

package authconfig

import (
	"errors"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authruntime"
)

// refusedSignIn answers a sign-in the provider accepted and the server
// refused, and reports whether that is what err is. The person is told why;
// the details go to the log.
func refusedSignIn(w http.ResponseWriter, r *http.Request, err error) bool {
	var refused *authruntime.RefusedError
	if !errors.As(err, &refused) {
		return false
	}
	logrus.Warnf("Refused a sign-in (remote address: %s): %s", r.RemoteAddr, refused)
	http.Error(w, refused.Reason, http.StatusForbidden)
	return true
}

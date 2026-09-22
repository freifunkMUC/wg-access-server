package apitokens

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"github.com/freifunkMUC/wg-access-server/internal/traces"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
)

// apiPrefix is the only part of the site a token opens. The web UI keeps
// requiring a browser session.
const apiPrefix = "/api/"

// Middleware authenticates API requests that carry a bearer token. It runs
// after the session middleware and takes precedence over a session: a
// request that names a token acts as that token, nothing else.
//
// A request with a token that does not work is refused here with a 401 rather
// than passed on - the redirect to the sign-in page it would get otherwise
// means nothing to a script. m is nil when API tokens are disabled.
func Middleware(m *Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			secret, ok := bearerToken(r)
			if !ok || !strings.HasPrefix(r.URL.Path, apiPrefix) {
				next.ServeHTTP(w, r)
				return
			}

			if m == nil {
				refuse(w, http.StatusUnauthorized, "API tokens are disabled on this server")
				return
			}

			identity, token, err := m.Authenticate(secret)
			if err != nil {
				logger := traces.Logger(r.Context()).WithField("remote_addr", r.RemoteAddr)
				var forbidden *ForbiddenError
				switch {
				case errors.As(err, &forbidden):
					logger.Warn(err)
					refuse(w, http.StatusForbidden, "the owner of this token has no access")
				case errors.Is(err, ErrInvalid), errors.Is(err, ErrExpired):
					logger.Warnf("Refused an API request: %s", err)
					refuse(w, http.StatusUnauthorized, err.Error())
				default:
					logger.Error(err)
					refuse(w, http.StatusInternalServerError, fmt.Sprintf("failed to check the token (trace = %s)", traces.TraceID(r.Context())))
				}
				return
			}

			ctx := authsession.SetIdentityCtx(r.Context(), &authsession.AuthSession{
				Identity: identity,
				APIToken: token.ID,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

func refuse(w http.ResponseWriter, status int, message string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintln(w, message)
}

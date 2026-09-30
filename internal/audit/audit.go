// Package audit records who changed what, so an operator can answer questions
// like "who deleted this device" from the server log. Entries are ordinary log
// lines carrying an "audit" field, which is what makes them greppable and
// shippable to wherever the rest of the logs go.
package audit

import (
	"context"
	"net"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/traces"
)

type contextKey string

const remoteAddrKey contextKey = "audit.remote-addr"

// Actions recorded by the audit log.
const (
	DeviceCreate = "device.create"
	DeviceDelete = "device.delete"
	DeviceRename = "device.rename"
	// DeviceAccess is an admin blocking a device or changing its expiry date.
	DeviceAccess = "device.access"
	// DeviceExpire is the server taking the access of a device away because
	// its expiry date has passed.
	DeviceExpire = "device.expire"
	// DeviceRotate is somebody replacing the key material of their device.
	// The keys themselves are not recorded: the public one says nothing an
	// operator needs, and writing key material into a log is a habit worth
	// not having.
	DeviceRotate = "device.rotate"
	// DeviceRoutes is an admin changing the networks behind a device.
	DeviceRoutes = "device.routes"
	UserDelete   = "user.delete"
	// UserPassword is somebody changing their own password. Neither the old
	// nor the new one is recorded, only that it happened and how many
	// sessions it ended.
	UserPassword = "user.password"
	// UserTwoFactor is somebody turning their own second factor on or off.
	UserTwoFactor = "user.two_factor"
	// UserTwoFactorReset is an admin taking somebody's second factor away,
	// for a person whose phone is gone.
	UserTwoFactorReset = "user.two_factor_reset"
	// UserPasskeyAdd and UserPasskeyDelete are somebody registering or
	// removing a passkey of their own.
	UserPasskeyAdd    = "user.passkey_add"
	UserPasskeyDelete = "user.passkey_delete"
	// UserRevoke is an admin taking somebody's access away in one action:
	// their devices are blocked, their tokens revoked, their sessions ended.
	UserRevoke = "user.revoke"
	// SessionDelete is somebody ending a browser session of their own.
	SessionDelete = "session.delete"
	TokenCreate   = "api_token.create"
	TokenDelete   = "api_token.delete"
)

// SystemActor stands in for wg-access-server itself, for changes that no user
// asked for - the automatic deletion of inactive devices, for instance.
const SystemActor = "system"

// WithRemoteAddr remembers the address a request came from. The API handlers
// are served through the HTTP router, so they see the context of the HTTP
// request and can record the address along with the action.
func WithRemoteAddr(ctx context.Context, remoteAddr string) context.Context {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return context.WithValue(ctx, remoteAddrKey, host)
}

// Middleware puts the client address of every request into its context.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(WithRemoteAddr(r.Context(), r.RemoteAddr)))
	})
}

func remoteAddr(ctx context.Context) string {
	if addr, ok := ctx.Value(remoteAddrKey).(string); ok {
		return addr
	}
	return ""
}

// Log records one action. The actor is taken from the session in ctx; without
// one the action is attributed to the server itself, which is what the
// background jobs do.
func Log(ctx context.Context, action string, fields logrus.Fields) {
	entry := logrus.Fields{
		"audit":     action,
		"actor":     SystemActor,
		"trace.id":  traces.TraceID(ctx),
		"component": "audit",
	}

	if user, err := authsession.CurrentUser(ctx); err == nil {
		entry["actor"] = user.Subject
		entry["actor_provider"] = user.Provider
		entry["actor_is_admin"] = user.Claims.IsAdmin()
		if token := authsession.APIToken(ctx); token != "" {
			entry["actor_api_token"] = token
		}
	}
	if addr := remoteAddr(ctx); addr != "" {
		entry["remote_addr"] = addr
	}
	for name, value := range fields {
		entry[name] = value
	}

	logrus.WithFields(entry).Info(action)
}

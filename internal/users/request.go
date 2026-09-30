package users

import (
	"context"
	"net/http"
)

type contextKey string

const requestKey contextKey = "users.request"

// WithRequest remembers the HTTP request an API call arrived with. Passkeys
// need it: which site this is, as a browser sees it, is what a credential is
// bound to, and that is in the request rather than in the API call.
func WithRequest(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, requestKey, r)
}

// RequestFrom returns that request, or nil outside an HTTP handler.
func RequestFrom(ctx context.Context) *http.Request {
	if r, ok := ctx.Value(requestKey).(*http.Request); ok {
		return r
	}
	return nil
}

// Middleware puts every request into its own context.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(WithRequest(r.Context(), r)))
	})
}

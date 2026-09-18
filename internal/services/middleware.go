package services

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/freifunkMUC/wg-access-server/internal/traces"
)

// contentSecurityPolicy keeps the browser from loading anything this server
// did not send. The web UI bundles its scripts, and the only thing it cannot
// do without is inline styles: MUI generates them at runtime and the login
// pages carry a <style> block.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"font-src 'self'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

// SecurityHeadersMiddleware sets the response headers that limit what a
// browser does with the web UI: no framing, no content sniffing, no referrer
// to wherever a client configuration was shared, and nothing loaded from
// another origin.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Content-Security-Policy", contentSecurityPolicy)

		// Only over TLS: a browser ignores the header on a plain HTTP
		// response anyway, and the web UI may be served over HTTP on purpose.
		// Behind a TLS terminating proxy the proxy sets this header.
		if r.TLS != nil {
			header.Set("Strict-Transport-Security", "max-age=31536000")
		}

		next.ServeHTTP(w, r)
	})
}

func TracesMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(traces.WithTraceID(r.Context())))
	})
}

func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				traces.Logger(r.Context()).
					WithField("stack", string(debug.Stack())).
					Error(err)
				w.WriteHeader(500)
				_, _ = fmt.Fprintf(w, "server error\ntrace = %s\n", traces.TraceID(r.Context()))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

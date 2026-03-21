package services

import (
	"crypto/subtle"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// basicAuthHandler wraps h with HTTP Basic Auth using a bcrypt hashed password.
func basicAuthHandler(h http.Handler, realm, username, passwordHash string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(username)) != 1 || bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(p)) != nil {
			w.Header().Set("WWW-Authenticate", "Basic realm=\""+realm+"\"")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

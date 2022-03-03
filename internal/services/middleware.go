package services

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"runtime/debug"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/freifunkMUC/wg-access-server/internal/traces"
)

func TracesMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(traces.WithTraceID(r.Context())))
	})
}

func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				logger := ctxlogrus.Extract(r.Context())

				if logger.Logger.Out == ioutil.Discard {
					logger = traces.Logger(r.Context())
				}

				logger.
					WithField("stack", string(debug.Stack())).
					Error(err)
				w.WriteHeader(500)
				fmt.Fprintf(w, "server error\ntrace = %s\n", traces.TraceID(r.Context()))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Package api serves the Connect API the web UI and the API tokens talk to.
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"connectrpc.com/connect"
	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"github.com/gorilla/mux"

	"github.com/freifunkMUC/wg-access-server/internal/apitokens"
	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/traces"
	"github.com/freifunkMUC/wg-access-server/proto/proto/protoconnect"
)

// maxRequestBytes bounds the size of a request message. The largest thing a
// client sends is a device name and a public key.
const maxRequestBytes = 1 << 20

type Services struct {
	Config        *config.AppConfig
	DeviceManager *devices.DeviceManager
	Tokens        *apitokens.Manager
	Wg            wgembed.WireGuardInterface
}

// Router serves the API through connectrpc. Besides its own protocol,
// Connect speaks gRPC-Web - which is what the web UI's client uses.
func Router(deps *Services) http.Handler {
	options := connect.WithHandlerOptions(
		connect.WithInterceptors(connect.UnaryInterceptorFunc(logInterceptor)),
		connect.WithRecover(recoverHandler),
		connect.WithReadMaxBytes(maxRequestBytes),
	)

	router := mux.NewRouter()
	for _, register := range []func() (string, http.Handler){
		func() (string, http.Handler) {
			return protoconnect.NewDevicesHandler(&DeviceService{DeviceManager: deps.DeviceManager}, options)
		},
		func() (string, http.Handler) {
			return protoconnect.NewUsersHandler(&UserService{DeviceManager: deps.DeviceManager, Tokens: deps.Tokens}, options)
		},
		func() (string, http.Handler) {
			return protoconnect.NewTokensHandler(&TokenService{Tokens: deps.Tokens, Enabled: deps.Config.EnableAPITokens}, options)
		},
		func() (string, http.Handler) {
			return protoconnect.NewServerHandler(&ServerService{Config: deps.Config, Wg: deps.Wg}, options)
		},
	} {
		path, handler := register()
		router.PathPrefix(path).Handler(handler)
	}

	return router
}

// logInterceptor reports failures with the trace id of the request.
func logInterceptor(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		res, err := next(ctx, req)
		if err != nil {
			traces.Logger(ctx).WithField("procedure", req.Spec().Procedure).Warn(err)
		}
		return res, err
	}
}

// recoverHandler keeps a panic in one request from taking the connection
// down with it, and gives the client a trace id to quote.
func recoverHandler(ctx context.Context, spec connect.Spec, _ http.Header, p any) error {
	traces.Logger(ctx).WithField("procedure", spec.Procedure).Errorf("panic: %v", p)
	return connect.NewError(connect.CodeInternal, fmt.Errorf("internal error (trace = %s)", traces.TraceID(ctx)))
}

// Each request gets its own error: connect adds headers to an error's
// metadata, so one shared between requests would be written concurrently.

func errNotAuthenticated() error {
	return connect.NewError(connect.CodePermissionDenied, errors.New("not authenticated"))
}

func errNotAdmin() error {
	return connect.NewError(connect.CodePermissionDenied, errors.New("must be an admin"))
}

// internalError logs err, which can hold storage or schema details, and
// hands the client only what failed and the trace id to find it in the log.
func internalError(ctx context.Context, err error, what string) error {
	traces.Logger(ctx).Error(err)
	return connect.NewError(connect.CodeInternal, fmt.Errorf("%s (trace = %s)", what, traces.TraceID(ctx)))
}

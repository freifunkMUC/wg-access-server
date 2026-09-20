package services

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"
	"github.com/gorilla/mux"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/freifunkMUC/wg-access-server/internal/traces"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
	"github.com/freifunkMUC/wg-access-server/proto/proto/protoconnect"
)

// ConnectRouter serves the same three services as ApiRouter, through
// connectrpc instead of the archived grpc-web wrapper. Connect speaks the
// gRPC-Web protocol itself, so the web UI's client works against it
// unchanged - which is what makes replacing the wrapper possible without
// touching the frontend.
//
// It is mounted next to the existing API for now, so both can be exercised
// side by side.
func ConnectRouter(deps *ApiServices) http.Handler {
	interceptors := connect.WithInterceptors(connect.UnaryInterceptorFunc(logInterceptor))

	devices := connectDevices{&DeviceService{DeviceManager: deps.DeviceManager}}
	users := connectUsers{&UserService{DeviceManager: deps.DeviceManager}}
	server := connectServer{&ServerService{Config: deps.Config, Wg: deps.Wg}}

	router := mux.NewRouter()
	for _, register := range []func() (string, http.Handler){
		func() (string, http.Handler) { return protoconnect.NewDevicesHandler(devices, interceptors) },
		func() (string, http.Handler) { return protoconnect.NewUsersHandler(users, interceptors) },
		func() (string, http.Handler) { return protoconnect.NewServerHandler(server, interceptors) },
	} {
		path, handler := register()
		router.PathPrefix(path).Handler(handler)
	}

	return router
}

// logInterceptor reports failures with the trace id of the request, the way
// the grpc interceptor does for the other API.
func logInterceptor(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		res, err := next(ctx, req)
		if err != nil {
			traces.Logger(ctx).WithField("procedure", req.Spec().Procedure).Warn(err)
		}
		return res, err
	}
}

// asConnectError keeps the status code the services report. Connect's codes
// carry the same numbers as the gRPC ones, so a "permission denied" stays a
// "permission denied" rather than turning into an unknown error.
func asConnectError(err error) error {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok {
		return connect.NewError(connect.Code(st.Code()), errors.New(st.Message()))
	}
	return err
}

// The adapters below unwrap the connect envelope and hand the request to the
// existing service implementations, so both APIs serve exactly the same code.

type connectDevices struct{ inner *DeviceService }

func (c connectDevices) AddDevice(ctx context.Context, req *connect.Request[proto.AddDeviceReq]) (*connect.Response[proto.Device], error) {
	res, err := c.inner.AddDevice(ctx, req.Msg)
	if err != nil {
		return nil, asConnectError(err)
	}
	return connect.NewResponse(res), nil
}

func (c connectDevices) ListDevices(ctx context.Context, req *connect.Request[proto.ListDevicesReq]) (*connect.Response[proto.ListDevicesRes], error) {
	res, err := c.inner.ListDevices(ctx, req.Msg)
	if err != nil {
		return nil, asConnectError(err)
	}
	return connect.NewResponse(res), nil
}

func (c connectDevices) DeleteDevice(ctx context.Context, req *connect.Request[proto.DeleteDeviceReq]) (*connect.Response[emptypb.Empty], error) {
	res, err := c.inner.DeleteDevice(ctx, req.Msg)
	if err != nil {
		return nil, asConnectError(err)
	}
	return connect.NewResponse(res), nil
}

func (c connectDevices) RenameDevice(ctx context.Context, req *connect.Request[proto.RenameDeviceReq]) (*connect.Response[proto.Device], error) {
	res, err := c.inner.RenameDevice(ctx, req.Msg)
	if err != nil {
		return nil, asConnectError(err)
	}
	return connect.NewResponse(res), nil
}

func (c connectDevices) ListAllDevices(ctx context.Context, req *connect.Request[proto.ListAllDevicesReq]) (*connect.Response[proto.ListAllDevicesRes], error) {
	res, err := c.inner.ListAllDevices(ctx, req.Msg)
	if err != nil {
		return nil, asConnectError(err)
	}
	return connect.NewResponse(res), nil
}

type connectUsers struct{ inner *UserService }

func (c connectUsers) ListUsers(ctx context.Context, req *connect.Request[proto.ListUsersReq]) (*connect.Response[proto.ListUsersRes], error) {
	res, err := c.inner.ListUsers(ctx, req.Msg)
	if err != nil {
		return nil, asConnectError(err)
	}
	return connect.NewResponse(res), nil
}

func (c connectUsers) DeleteUser(ctx context.Context, req *connect.Request[proto.DeleteUserReq]) (*connect.Response[emptypb.Empty], error) {
	res, err := c.inner.DeleteUser(ctx, req.Msg)
	if err != nil {
		return nil, asConnectError(err)
	}
	return connect.NewResponse(res), nil
}

type connectServer struct{ inner *ServerService }

func (c connectServer) Info(ctx context.Context, req *connect.Request[proto.InfoReq]) (*connect.Response[proto.InfoRes], error) {
	res, err := c.inner.Info(ctx, req.Msg)
	if err != nil {
		return nil, asConnectError(err)
	}
	return connect.NewResponse(res), nil
}

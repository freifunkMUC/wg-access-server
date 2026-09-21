package services

import (
	"context"

	"connectrpc.com/connect"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

type UserService struct {
	DeviceManager *devices.DeviceManager
}

func (d *UserService) ListUsers(ctx context.Context, _ *connect.Request[proto.ListUsersReq]) (*connect.Response[proto.ListUsersRes], error) {
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}

	if !user.Claims.Has("admin", "true") {
		return nil, errNotAdmin()
	}

	users, err := d.DeviceManager.ListUsers()
	if err != nil {
		return nil, internalError(ctx, err, "failed to retrieve users")
	}

	return connect.NewResponse(&proto.ListUsersRes{
		Items: mapUsers(users),
	}), nil
}

func (d *UserService) DeleteUser(ctx context.Context, request *connect.Request[proto.DeleteUserReq]) (*connect.Response[emptypb.Empty], error) {
	req := request.Msg
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}

	if !user.Claims.Has("admin", "true") {
		return nil, errNotAdmin()
	}

	if err := d.DeviceManager.DeleteDevicesForUser(req.Name); err != nil {
		return nil, internalError(ctx, err, "failed to delete user")
	}

	audit.Log(ctx, audit.UserDelete, logrus.Fields{"target_user": req.Name})

	return connect.NewResponse(&emptypb.Empty{}), nil
}

func mapUser(u *devices.User) *proto.User {
	return &proto.User{
		Name:        u.Name,
		DisplayName: u.DisplayName,
	}
}

func mapUsers(users []*devices.User) []*proto.User {
	items := []*proto.User{}
	for _, u := range users {
		items = append(items, mapUser(u))
	}
	return items
}

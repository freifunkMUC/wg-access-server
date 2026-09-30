package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/freifunkMUC/wg-access-server/internal/apitokens"
	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/websessions"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

type UserService struct {
	DeviceManager *devices.DeviceManager
	// Tokens is nil in tests that do not care about them.
	Tokens *apitokens.Manager
	// Sessions is nil in tests that do not care about them.
	Sessions *websessions.Manager
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

	// The ways in first: the tokens and the sessions are access, the devices
	// are what it is for. The tokens are revoked even while tokens are
	// disabled, so that enabling them again cannot bring back the tokens of a
	// deleted user.
	if d.Tokens != nil {
		if _, err := d.Tokens.DeleteForOwner(req.Name); err != nil {
			return nil, internalError(ctx, err, "failed to delete user")
		}
	}

	if d.Sessions != nil {
		if _, err := d.Sessions.EndAllForOwner(req.Name); err != nil {
			return nil, internalError(ctx, err, "failed to delete user")
		}
	}

	if err := d.DeviceManager.DeleteDevicesForUser(req.Name); err != nil {
		return nil, internalError(ctx, err, "failed to delete user")
	}

	// Last, so that a failure here leaves a user without access rather than
	// access without a user.
	if err := d.DeviceManager.ForgetUser(req.Name); err != nil {
		return nil, internalError(ctx, err, "failed to delete user")
	}

	audit.Log(ctx, audit.UserDelete, logrus.Fields{"target_user": req.Name})

	return connect.NewResponse(&emptypb.Empty{}), nil
}

// RevokeAccess takes somebody's access away without deleting anything: their
// devices are blocked, their API tokens revoked and their sessions ended. It
// is what an admin reaches for when a person leaves or a laptop is lost and
// deleting the user would be too much - the devices keep their keys and
// addresses, so lifting the blocks gives the access back without anybody
// setting up their client anew.
func (d *UserService) RevokeAccess(ctx context.Context, request *connect.Request[proto.RevokeAccessReq]) (*connect.Response[proto.RevokeAccessRes], error) {
	req := request.Msg
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}

	if !user.Claims.Has("admin", "true") {
		return nil, errNotAdmin()
	}

	if req.GetName() == user.Subject {
		// It would work - and sign the admin out mid-action, with their own
		// devices blocked. Whoever wants that can block their devices one by
		// one and sign out.
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this would take your own access away: block your devices and sign out instead"))
	}

	// The ways in first, as in DeleteUser: a session or a token that survives
	// until the devices are blocked is a way back in. The tokens go even
	// while tokens are disabled, so that enabling them again cannot hand a
	// revoked user a way in.
	res := &proto.RevokeAccessRes{}

	if d.Tokens != nil {
		deleted, err := d.Tokens.DeleteForOwner(req.GetName())
		if err != nil {
			return nil, internalError(ctx, err, "failed to revoke the access of the user")
		}
		res.TokensDeleted = int32(deleted)
	}

	if d.Sessions != nil {
		ended, err := d.Sessions.EndAllForOwner(req.GetName())
		if err != nil {
			return nil, internalError(ctx, err, "failed to revoke the access of the user")
		}
		res.SessionsEnded = int32(ended)
	}

	blocked, err := d.DeviceManager.BlockDevicesForUser(req.GetName())
	if err != nil {
		return nil, internalError(ctx, err, "failed to revoke the access of the user")
	}
	res.DevicesBlocked = int32(blocked)

	audit.Log(ctx, audit.UserRevoke, logrus.Fields{
		"target_user":     req.GetName(),
		"devices_blocked": res.GetDevicesBlocked(),
		"tokens_deleted":  res.GetTokensDeleted(),
		"sessions_ended":  res.GetSessionsEnded(),
	})

	return connect.NewResponse(res), nil
}

func mapUser(u *devices.User) *proto.User {
	return &proto.User{
		Name:        u.Name,
		DisplayName: u.DisplayName,
		LastLogin:   timeToTimestamp(u.LastLogin),
		Policies:    u.Policies,
	}
}

func mapUsers(users []*devices.User) []*proto.User {
	items := []*proto.User{}
	for _, u := range users {
		items = append(items, mapUser(u))
	}
	return items
}

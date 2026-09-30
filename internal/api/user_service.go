package api

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/freifunkMUC/wg-access-server/internal/apitokens"
	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authconfig"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/users"
	"github.com/freifunkMUC/wg-access-server/internal/websessions"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

type UserService struct {
	DeviceManager *devices.DeviceManager
	// Passwords changes a password somebody set for themselves. It is nil
	// when no built-in provider is configured, and then there is nothing to
	// change here.
	Passwords *users.Passwords
	// TwoFactor is the second factor of the built-in sign-in, nil for the
	// same reason.
	TwoFactor *users.TwoFactor
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

// minPasswordLength is what a password set here has to be. Long enough to be
// worth the bcrypt round, short enough that people do not write it down; the
// configured entries are not checked against it, because those are an admin's
// business and not ours to refuse at sign-in.
const minPasswordLength = 10

// ChangePassword replaces the password of whoever is asking. Only the built-in
// providers have one to change - with an identity provider the password is
// theirs - and only the person themselves can: an admin who wants somebody out
// revokes their access, which does not need their password.
//
// The other sessions end with it. Whoever knew the old password may have one,
// and a password change that leaves them signed in changes nothing for them.
func (d *UserService) ChangePassword(ctx context.Context, request *connect.Request[proto.ChangePasswordReq]) (*connect.Response[proto.ChangePasswordRes], error) {
	req := request.Msg
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}

	if d.Passwords == nil || !authconfig.HasPassword(user.Provider) {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this account's password is not kept here: change it where you sign in"))
	}

	if len(req.GetNewPassword()) < minPasswordLength {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the new password has to be at least %d characters", minPasswordLength))
	}

	if err := d.Passwords.Change(user.Subject, req.GetCurrentPassword(), req.GetNewPassword()); err != nil {
		if errors.Is(err, users.ErrWrongPassword) {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("that is not your current password"))
		}
		if errors.Is(err, users.ErrNoPasswordHere) {
			return nil, connect.NewError(connect.CodeFailedPrecondition,
				errors.New("this account is not one the server keeps a password for"))
		}
		return nil, internalError(ctx, err, "failed to change the password")
	}

	// Whoever knew the old password may be holding a session made with it.
	// The one asking stays: signing somebody out of the page they are on to
	// tell them their password changed helps nobody.
	ended := 0
	if d.Sessions != nil {
		keep := ""
		if session, err := d.Sessions.Find(authsession.CurrentSessionID(ctx)); err == nil {
			keep = session.ID
		}
		if ended, err = d.Sessions.EndOthers(user.Subject, keep); err != nil {
			// The password did change; saying it failed would be worse than
			// saying that one part of it did not.
			logrus.Error(fmt.Errorf("failed to end the other sessions after a password change: %w", err))
		}
	}

	audit.Log(ctx, audit.UserPassword, logrus.Fields{"sessions_ended": ended})

	return connect.NewResponse(&proto.ChangePasswordRes{SessionsEnded: int32(ended)}), nil
}

// twoFactorFor returns the second factor of whoever is asking, or the reason
// they have none to speak of.
func (d *UserService) twoFactorFor(ctx context.Context) (*authsession.Identity, error) {
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}
	if d.TwoFactor == nil || !authconfig.HasPassword(user.Provider) {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this account signs in through an identity provider: set up a second factor there"))
	}
	return user, nil
}

// StartTwoFactor hands out a secret for an authenticator app. Nothing is
// asked of the user until they confirm it with a code, so a QR code somebody
// walked away from locks nobody out.
func (d *UserService) StartTwoFactor(ctx context.Context, _ *connect.Request[proto.StartTwoFactorReq]) (*connect.Response[proto.StartTwoFactorRes], error) {
	user, err := d.twoFactorFor(ctx)
	if err != nil {
		return nil, err
	}

	account := user.Name
	if account == "" {
		account = user.Subject
	}

	secret, uri, err := d.TwoFactor.Start(user.Subject, account)
	if err != nil {
		if errors.Is(err, users.ErrTwoFactorSet) {
			return nil, connect.NewError(connect.CodeFailedPrecondition,
				errors.New("this account already has a second factor: turn it off first"))
		}
		return nil, internalError(ctx, err, "failed to start the two-factor setup")
	}

	return connect.NewResponse(&proto.StartTwoFactorRes{Secret: secret, Uri: uri}), nil
}

// ConfirmTwoFactor turns it on, once a code from the app proves the app has
// the secret, and returns the recovery codes - the only time they exist
// outside the person's own hands.
func (d *UserService) ConfirmTwoFactor(ctx context.Context, request *connect.Request[proto.ConfirmTwoFactorReq]) (*connect.Response[proto.ConfirmTwoFactorRes], error) {
	user, err := d.twoFactorFor(ctx)
	if err != nil {
		return nil, err
	}

	codes, err := d.TwoFactor.Confirm(user.Subject, request.Msg.GetCode())
	if err != nil {
		switch {
		case errors.Is(err, users.ErrWrongCode):
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("that code is not right"))
		case errors.Is(err, users.ErrNoTwoFactor):
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("start the setup first"))
		case errors.Is(err, users.ErrTwoFactorSet):
			return nil, connect.NewError(connect.CodeFailedPrecondition,
				errors.New("this account already has a second factor"))
		}
		return nil, internalError(ctx, err, "failed to turn the second factor on")
	}

	audit.Log(ctx, audit.UserTwoFactor, logrus.Fields{"enabled": true})

	return connect.NewResponse(&proto.ConfirmTwoFactorRes{RecoveryCodes: codes}), nil
}

// DisableTwoFactor turns it off. It asks for the password, so that a browser
// somebody left signed in is not enough to take it away.
func (d *UserService) DisableTwoFactor(ctx context.Context, request *connect.Request[proto.DisableTwoFactorReq]) (*connect.Response[emptypb.Empty], error) {
	user, err := d.twoFactorFor(ctx)
	if err != nil {
		return nil, err
	}

	if err := d.TwoFactor.Disable(user.Subject, request.Msg.GetPassword()); err != nil {
		if errors.Is(err, users.ErrWrongPassword) {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("that is not your password"))
		}
		return nil, internalError(ctx, err, "failed to turn the second factor off")
	}

	audit.Log(ctx, audit.UserTwoFactor, logrus.Fields{"enabled": false})

	return connect.NewResponse(&emptypb.Empty{}), nil
}

// ResetTwoFactor takes somebody's second factor away, for an admin helping a
// person whose phone is gone. Their password then signs them in again, so it
// is as much trust as handing out a password - and it is recorded as such.
func (d *UserService) ResetTwoFactor(ctx context.Context, request *connect.Request[proto.ResetTwoFactorReq]) (*connect.Response[emptypb.Empty], error) {
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}
	if !user.Claims.Has("admin", "true") {
		return nil, errNotAdmin()
	}
	if d.TwoFactor == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this server keeps no second factors"))
	}

	if err := d.TwoFactor.Reset(request.Msg.GetName()); err != nil {
		if errors.Is(err, users.ErrNoTwoFactor) || errors.Is(err, users.ErrNoPasswordHere) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("this user has no second factor"))
		}
		return nil, internalError(ctx, err, "failed to remove the second factor")
	}

	audit.Log(ctx, audit.UserTwoFactorReset, logrus.Fields{"target_user": request.Msg.GetName()})

	return connect.NewResponse(&emptypb.Empty{}), nil
}

func mapUser(u *devices.User) *proto.User {
	return &proto.User{
		Name:        u.Name,
		DisplayName: u.DisplayName,
		LastLogin:   timeToTimestamp(u.LastLogin),
		Policies:    u.Policies,
		TwoFactor:   u.TwoFactor,
	}
}

func mapUsers(users []*devices.User) []*proto.User {
	items := []*proto.User{}
	for _, u := range users {
		items = append(items, mapUser(u))
	}
	return items
}

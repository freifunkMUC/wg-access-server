package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/websessions"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

// SessionService lets somebody see where they are signed in and end those
// sessions. Everybody manages their own: an admin taking another person's
// access away is a different thing, and it takes their devices and tokens
// with it.
type SessionService struct {
	Sessions *websessions.Manager
}

func (s *SessionService) ListSessions(ctx context.Context, _ *connect.Request[proto.ListSessionsReq]) (*connect.Response[proto.ListSessionsRes], error) {
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}

	sessions, err := s.Sessions.List(user.Subject)
	if err != nil {
		return nil, internalError(ctx, err, "failed to retrieve sessions")
	}

	return connect.NewResponse(&proto.ListSessionsRes{
		Items: mapSessions(sessions, s.currentID(ctx)),
	}), nil
}

func (s *SessionService) DeleteSession(ctx context.Context, request *connect.Request[proto.DeleteSessionReq]) (*connect.Response[emptypb.Empty], error) {
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}
	if err := refuseAPIToken(ctx); err != nil {
		return nil, err
	}

	if err := s.Sessions.Delete(user.Subject, request.Msg.GetId()); err != nil {
		if errors.Is(err, websessions.ErrInvalid) {
			// A session of somebody else is reported as missing rather than
			// refused: an id that exists must not be distinguishable from one
			// that does not.
			return nil, connect.NewError(connect.CodeNotFound, errors.New("session not found"))
		}
		return nil, internalError(ctx, err, "failed to end the session")
	}

	audit.Log(ctx, audit.SessionDelete, logrus.Fields{"session": request.Msg.GetId()})

	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *SessionService) DeleteOtherSessions(ctx context.Context, _ *connect.Request[proto.DeleteOtherSessionsReq]) (*connect.Response[proto.DeleteOtherSessionsRes], error) {
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}
	if err := refuseAPIToken(ctx); err != nil {
		return nil, err
	}

	current := s.currentID(ctx)
	if current == "" {
		// Without a session there is none to keep, and ending every session
		// of somebody is not what this is for.
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this needs a browser session: there is none to keep"))
	}

	ended, err := s.Sessions.EndOthers(user.Subject, current)
	if err != nil {
		return nil, internalError(ctx, err, "failed to end the sessions")
	}

	audit.Log(ctx, audit.SessionDelete, logrus.Fields{"sessions": ended, "reason": "all others"})

	return connect.NewResponse(&proto.DeleteOtherSessionsRes{Ended: int32(ended)}), nil
}

// currentID is the id of the session the request came with, as it is stored -
// never the one from the cookie.
func (s *SessionService) currentID(ctx context.Context) string {
	session, err := s.Sessions.Find(authsession.CurrentSessionID(ctx))
	if err != nil {
		return ""
	}
	return session.ID
}

func mapSession(session *storage.Session, current string) *proto.Session {
	return &proto.Session{
		Id:         session.ID,
		UserAgent:  session.UserAgent,
		RemoteAddr: session.RemoteAddr,
		CreatedAt:  timeToTimestamp(&session.CreatedAt),
		LastSeenAt: timeToTimestamp(&session.LastSeenAt),
		ExpiresAt:  timeToTimestamp(&session.ExpiresAt),
		Current:    session.ID == current,
	}
}

func mapSessions(sessions []*storage.Session, current string) []*proto.Session {
	items := []*proto.Session{}
	for _, session := range sessions {
		items = append(items, mapSession(session, current))
	}
	return items
}

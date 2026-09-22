package services

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/freifunkMUC/wg-access-server/internal/apitokens"
	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

type TokenService struct {
	Tokens  *apitokens.Manager
	Enabled bool
}

func (s *TokenService) CreateToken(ctx context.Context, request *connect.Request[proto.CreateTokenReq]) (*connect.Response[proto.CreateTokenRes], error) {
	req := request.Msg
	user, err := s.user(ctx)
	if err != nil {
		return nil, err
	}

	// A token that could issue tokens would outlive its own expiry and
	// revocation through the ones it created.
	if authsession.APIToken(ctx) != "" {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("tokens can only be created in the web UI"))
	}

	var expiresAt *time.Time
	if req.GetExpiresAt() != nil {
		t := req.GetExpiresAt().AsTime()
		expiresAt = &t
	}
	secret, token, err := s.Tokens.Create(user, req.GetName(), expiresAt)
	if err != nil {
		var validation *apitokens.ValidationError
		if errors.As(err, &validation) {
			return nil, connect.NewError(connect.CodeInvalidArgument, validation)
		}
		return nil, internalError(ctx, err, "failed to create token")
	}

	fields := logrus.Fields{"token": token.ID, "token_name": token.Name}
	if token.ExpiresAt != nil {
		fields["expires_at"] = token.ExpiresAt
	}
	audit.Log(ctx, audit.TokenCreate, fields)

	return connect.NewResponse(&proto.CreateTokenRes{
		Token:  mapToken(token),
		Secret: secret,
	}), nil
}

func (s *TokenService) ListTokens(ctx context.Context, _ *connect.Request[proto.ListTokensReq]) (*connect.Response[proto.ListTokensRes], error) {
	user, err := s.user(ctx)
	if err != nil {
		return nil, err
	}

	tokens, err := s.Tokens.List(user.Subject)
	if err != nil {
		return nil, internalError(ctx, err, "failed to retrieve tokens")
	}
	return connect.NewResponse(&proto.ListTokensRes{Items: mapTokens(tokens)}), nil
}

func (s *TokenService) DeleteToken(ctx context.Context, request *connect.Request[proto.DeleteTokenReq]) (*connect.Response[emptypb.Empty], error) {
	user, err := s.user(ctx)
	if err != nil {
		return nil, err
	}

	token, err := s.Tokens.Delete(user, request.Msg.GetId())
	if errors.Is(err, storage.ErrTokenNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such token"))
	}
	if err != nil {
		return nil, internalError(ctx, err, "failed to delete token")
	}

	audit.Log(ctx, audit.TokenDelete, logrus.Fields{
		"token":      token.ID,
		"token_name": token.Name,
		"owner":      token.Owner,
	})

	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *TokenService) ListAllTokens(ctx context.Context, _ *connect.Request[proto.ListAllTokensReq]) (*connect.Response[proto.ListAllTokensRes], error) {
	user, err := s.user(ctx)
	if err != nil {
		return nil, err
	}
	if !user.Claims.IsAdmin() {
		return nil, errNotAdmin()
	}

	tokens, err := s.Tokens.List("")
	if err != nil {
		return nil, internalError(ctx, err, "failed to retrieve tokens")
	}
	return connect.NewResponse(&proto.ListAllTokensRes{Items: mapTokens(tokens)}), nil
}

// user returns the user a request comes from, once it is clear that tokens
// can be used at all.
func (s *TokenService) user(ctx context.Context) (*authsession.Identity, error) {
	if !s.Enabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("API tokens are disabled on this server"))
	}
	user, err := authsession.CurrentUser(ctx)
	if err != nil {
		return nil, errNotAuthenticated()
	}
	return user, nil
}

func mapToken(t *storage.APIToken) *proto.Token {
	token := &proto.Token{
		Id:         t.ID,
		Name:       t.Name,
		Owner:      t.Owner,
		CreatedAt:  TimeToTimestamp(&t.CreatedAt),
		ExpiresAt:  TimeToTimestamp(t.ExpiresAt),
		LastUsedAt: TimeToTimestamp(t.LastUsedAt),
	}
	// the display name is part of the identity the token acts as
	identity := &authsession.Identity{}
	if err := json.Unmarshal([]byte(t.Identity), identity); err == nil {
		token.OwnerName = identity.Name
	}
	return token
}

func mapTokens(tokens []*storage.APIToken) []*proto.Token {
	items := []*proto.Token{}
	for _, t := range tokens {
		items = append(items, mapToken(t))
	}
	return items
}

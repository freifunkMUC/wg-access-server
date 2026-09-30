package api

import (
	"testing"

	"connectrpc.com/connect"

	"github.com/freifunkMUC/wg-access-server/proto/proto"
)

// A signed-in session must not be a way to guess the password.
func TestChangingThePasswordLimitsWrongOnes(t *testing.T) {
	service, ctx := twoFactorService(t)

	for i := 0; i < 5; i++ {
		_, err := service.ChangePassword(ctx, connect.NewRequest(&proto.ChangePasswordReq{
			CurrentPassword: "wrong", NewPassword: "a new password",
		}))
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("wrong password %d: %v, want permission denied", i+1, err)
		}
	}

	_, err := service.ChangePassword(ctx, connect.NewRequest(&proto.ChangePasswordReq{
		CurrentPassword: configuredPassword, NewPassword: "a new password",
	}))
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("right password after too many wrong ones: %v, want resource exhausted", err)
	}
}

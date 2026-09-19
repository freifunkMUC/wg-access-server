package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

func lastEntry(t *testing.T, hook *logrustest.Hook) *logrus.Entry {
	t.Helper()
	entry := hook.LastEntry()
	if entry == nil {
		t.Fatal("nothing was logged")
	}
	return entry
}

// Without a session the change was made by the server itself, not by a user.
func TestLogWithoutASessionIsAttributedToTheSystem(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	Log(context.Background(), DeviceDelete, logrus.Fields{"device": "laptop"})

	entry := lastEntry(t, hook)
	if got := entry.Data["actor"]; got != SystemActor {
		t.Errorf("actor = %v, want %q", got, SystemActor)
	}
	if got := entry.Data["audit"]; got != DeviceDelete {
		t.Errorf("audit = %v, want %q", got, DeviceDelete)
	}
	if got := entry.Data["device"]; got != "laptop" {
		t.Errorf("device = %v, want laptop", got)
	}
}

func TestMiddlewarePutsTheClientAddressIntoTheContext(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Log(r.Context(), DeviceCreate, nil)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:44321"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	// the port is not part of the identity of a client
	if got := lastEntry(t, hook).Data["remote_addr"]; got != "203.0.113.9" {
		t.Errorf("remote_addr = %v, want 203.0.113.9", got)
	}
}

func TestRemoteAddrWithoutAPort(t *testing.T) {
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	Log(WithRemoteAddr(context.Background(), "203.0.113.9"), DeviceCreate, nil)

	if got := lastEntry(t, hook).Data["remote_addr"]; got != "203.0.113.9" {
		t.Errorf("remote_addr = %v, want 203.0.113.9", got)
	}
}

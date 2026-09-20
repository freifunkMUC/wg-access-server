package services

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/freifunkMUC/wg-access-server/proto/proto"
	"github.com/freifunkMUC/wg-access-server/proto/proto/protoconnect"
)

// TestConnectAgainstARunningServer drives the real binary: log in through the
// web login, then call the Connect endpoint with the gRPC-Web protocol the
// browser client uses. It needs the server binary, so it only runs when
// WG_BINARY points at one (the CI builds it first).
func TestConnectAgainstARunningServer(t *testing.T) {
	binary := os.Getenv("WG_BINARY")
	if binary == "" {
		t.Skip("WG_BINARY not set")
	}

	cmd := exec.Command(binary, "serve",
		"--no-wireguard-enabled", "--no-dns-enabled", "--no-https-enabled",
		"--port", "18099", "--storage", "memory://", "--admin-password", "hunter2")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	base := "http://localhost:18099"
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// wait for the server
	for i := 0; i < 50; i++ {
		if res, err := client.Get(base + "/health"); err == nil {
			_ = res.Body.Close()
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// log in the way the login page does
	res, err := client.PostForm(base+"/signin/simpleauth", url.Values{
		"username": {"admin"}, "password": {"hunter2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if len(jar.Cookies(mustParse(t, base))) == 0 {
		t.Fatal("no session cookie after the login")
	}

	devices := protoconnect.NewDevicesClient(client, base+"/connect", connect.WithGRPCWeb())

	added, err := devices.AddDevice(context.Background(), connect.NewRequest(&proto.AddDeviceReq{
		Name:      "laptop",
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}))
	if err != nil {
		t.Fatalf("AddDevice over gRPC-Web against the running server failed: %v", err)
	}
	t.Logf("added device %q with address %q", added.Msg.Name, added.Msg.Address)

	listed, err := devices.ListDevices(context.Background(), connect.NewRequest(&proto.ListDevicesReq{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Msg.Items) != 1 {
		t.Fatalf("got %d devices, want 1", len(listed.Msg.Items))
	}
	t.Logf("listed %d device(s): %s", len(listed.Msg.Items), listed.Msg.Items[0].Name)

	// and the old API still answers on /api
	server := protoconnect.NewServerClient(client, base+"/connect", connect.WithGRPCWeb())
	info, err := server.Info(context.Background(), connect.NewRequest(&proto.InfoReq{}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(info.Msg.AllowedIps, "0.0.0.0/0") {
		t.Errorf("unexpected server info: %+v", info.Msg)
	}
	t.Logf("server info: allowedIps=%q isAdmin=%v", info.Msg.AllowedIps, info.Msg.IsAdmin)
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

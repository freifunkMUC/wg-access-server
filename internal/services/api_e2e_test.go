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

// startServer runs the real binary and logs in through the web login, the
// way the browser does. It needs the server binary, so it only runs when
// WG_BINARY points at one (the CI builds it first).
func startServer(t *testing.T, port string, flags ...string) (string, *http.Client) {
	t.Helper()
	binary := os.Getenv("WG_BINARY")
	if binary == "" {
		t.Skip("WG_BINARY not set")
	}

	args := append([]string{"serve",
		"--no-wireguard-enabled", "--no-dns-enabled", "--no-https-enabled",
		"--port", port, "--storage", "memory://", "--admin-password", "hunter2"}, flags...)
	cmd := exec.Command(binary, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	base := "http://localhost:" + port
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

	return base, client
}

// TestConnectAgainstARunningServer calls the API with the gRPC-Web protocol
// the browser client uses.
func TestConnectAgainstARunningServer(t *testing.T) {
	base, client := startServer(t, "18099")

	devices := protoconnect.NewDevicesClient(client, base+"/api", connect.WithGRPCWeb())

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

	server := protoconnect.NewServerClient(client, base+"/api", connect.WithGRPCWeb())
	info, err := server.Info(context.Background(), connect.NewRequest(&proto.InfoReq{}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(info.Msg.AllowedIps, "0.0.0.0/0") {
		t.Errorf("unexpected server info: %+v", info.Msg)
	}
	t.Logf("server info: allowedIps=%q isAdmin=%v", info.Msg.AllowedIps, info.Msg.IsAdmin)
}

// bearer is an HTTP client that sends an API token and nothing else - no
// session cookie, like a script.
type bearer struct {
	token string
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

// TestAPITokensAgainstARunningServer creates a token in a browser session and
// uses it the way a script would: the plain Connect protocol, no cookie.
func TestAPITokensAgainstARunningServer(t *testing.T) {
	base, session := startServer(t, "18097", "--enable-api-tokens")
	ctx := context.Background()

	created, err := protoconnect.NewTokensClient(session, base+"/api", connect.WithGRPCWeb()).
		CreateToken(ctx, connect.NewRequest(&proto.CreateTokenReq{Name: "e2e"}))
	if err != nil {
		t.Fatal(err)
	}
	secret := created.Msg.Secret

	script := &http.Client{Transport: bearer{secret}}
	info, err := protoconnect.NewServerClient(script, base+"/api").Info(ctx, connect.NewRequest(&proto.InfoReq{}))
	if err != nil {
		t.Fatalf("the token does not work: %v", err)
	}
	if !info.Msg.IsAdmin || !info.Msg.ApiTokensEnabled {
		t.Errorf("isAdmin = %v, apiTokensEnabled = %v: want the admin's token on a server with tokens", info.Msg.IsAdmin, info.Msg.ApiTokensEnabled)
	}

	_, err = protoconnect.NewTokensClient(script, base+"/api").
		CreateToken(ctx, connect.NewRequest(&proto.CreateTokenReq{Name: "child"}))
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Errorf("a token created a token: code = %v, want %v", code, connect.CodePermissionDenied)
	}

	// a wrong token is refused, not sent to the sign-in page
	wrong := &http.Client{Transport: bearer{"wgas_wrong"}}
	_, err = protoconnect.NewServerClient(wrong, base+"/api").Info(ctx, connect.NewRequest(&proto.InfoReq{}))
	if code := connect.CodeOf(err); code != connect.CodeUnauthenticated {
		t.Errorf("wrong token: code = %v (%v), want %v", code, err, connect.CodeUnauthenticated)
	}

	// the web UI does not take tokens
	noRedirect := &http.Client{
		Transport:     bearer{secret},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	res, err := noRedirect.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusTemporaryRedirect || res.Header.Get("Location") != "/signin" {
		t.Errorf("web UI with a token: %d to %q, want the redirect to /signin", res.StatusCode, res.Header.Get("Location"))
	}

	_, err = protoconnect.NewTokensClient(session, base+"/api", connect.WithGRPCWeb()).
		DeleteToken(ctx, connect.NewRequest(&proto.DeleteTokenReq{Id: created.Msg.Token.Id}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = protoconnect.NewServerClient(script, base+"/api").Info(ctx, connect.NewRequest(&proto.InfoReq{}))
	if code := connect.CodeOf(err); code != connect.CodeUnauthenticated {
		t.Errorf("revoked token: code = %v, want %v", code, connect.CodeUnauthenticated)
	}
}

// Without --enable-api-tokens a token is refused even if one exists.
func TestAPITokensAreOffByDefault(t *testing.T) {
	base, _ := startServer(t, "18096")
	script := &http.Client{Transport: bearer{"wgas_anything"}}
	_, err := protoconnect.NewServerClient(script, base+"/api").Info(context.Background(), connect.NewRequest(&proto.InfoReq{}))
	if code := connect.CodeOf(err); code != connect.CodeUnauthenticated {
		t.Errorf("code = %v, want %v", code, connect.CodeUnauthenticated)
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

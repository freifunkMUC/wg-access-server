package authnz

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authconfig"
	"github.com/freifunkMUC/wg-access-server/internal/users"
)

// fakeTwoFactor stands in for what the server keeps: who is asked for a code,
// and which code is theirs.
type fakeTwoFactor struct {
	enabled map[string]bool
	codes   map[string]string
	checked int
}

func (f *fakeTwoFactor) Enabled(subject string) bool { return f.enabled[subject] }

// the codes are the only second factor this fake has
func (f *fakeTwoFactor) CodesEnabled(subject string) bool { return f.enabled[subject] }

func (f *fakeTwoFactor) Check(subject string, code string) bool {
	f.checked++
	want, ok := f.codes[subject]
	return ok && code == want
}

// simpleAuthMiddleware drives the real router: the sign-in page posts to it,
// and what comes back is what a browser would get.
func simpleAuthMiddleware(t *testing.T, username, password string, twoFactor *fakeTwoFactor) *AuthMiddleware {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}

	opts := []Option{}
	if twoFactor != nil {
		opts = append(opts, WithTwoFactor(twoFactor))
	}

	m, err := New(authconfig.AuthConfig{
		ProviderConfig: authconfig.ProviderConfig{
			Simple: &authconfig.SimpleAuthConfig{Users: []string{username + ":" + string(hash)}},
		},
	}, nil, testSessions(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// post sends a form to the simple auth endpoint, carrying the cookies it was
// given before - as a browser does.
func post(t *testing.T, m *AuthMiddleware, form url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/signin/simpleauth", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	m.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rr, r)
	return rr
}

func signedIn(rr *httptest.ResponseRecorder) bool {
	// the sign-in ends in a redirect away from the form; the code page and a
	// refused attempt both answer with a page
	return rr.Code == http.StatusSeeOther || rr.Code == http.StatusFound
}

// Somebody without a second factor signs in with a password, as before.
func TestSignInWithoutASecondFactor(t *testing.T) {
	m := simpleAuthMiddleware(t, "alice", "the-password", &fakeTwoFactor{})

	rr := post(t, m, url.Values{"username": {"alice"}, "password": {"the-password"}}, nil)

	if !signedIn(rr) {
		t.Fatalf("code = %d, want a redirect: the password alone should sign in", rr.Code)
	}
}

// With one, the password is half the login: the page asks for a code, and
// nothing about that half is a session yet.
func TestSignInAsksForTheCode(t *testing.T) {
	twoFactor := &fakeTwoFactor{
		enabled: map[string]bool{"alice": true},
		codes:   map[string]string{"alice": "123456"},
	}
	m := simpleAuthMiddleware(t, "alice", "the-password", twoFactor)

	first := post(t, m, url.Values{"username": {"alice"}, "password": {"the-password"}}, nil)
	if signedIn(first) {
		t.Fatal("the password alone signed in although a second factor is set up")
	}
	body := first.Body.String()
	if !strings.Contains(body, `name="code"`) {
		t.Fatalf("the page does not ask for a code: %s", body)
	}
	if strings.Contains(body, `name="password"`) {
		t.Error("the page still asks for the password as well")
	}

	// the cookie from that step is not a login
	cookies := first.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("nothing was remembered between the two steps")
	}

	// the wrong code does not sign in, and does not lose the pending login
	wrong := post(t, m, url.Values{"code": {"000000"}}, cookies)
	if signedIn(wrong) {
		t.Fatal("a wrong code signed in")
	}
	if !strings.Contains(wrong.Body.String(), `name="code"`) {
		t.Error("a wrong code did not ask again")
	}

	// the right one does
	right := post(t, m, url.Values{"code": {"123456"}}, cookies)
	if !signedIn(right) {
		t.Fatalf("code = %d, want a redirect: the right code should sign in", right.Code)
	}
}

// A code without a password step before it is nothing: whoever posts one
// straight to the endpoint is sent back to the start.
func TestACodeWithoutAPasswordStepSignsNobodyIn(t *testing.T) {
	twoFactor := &fakeTwoFactor{
		enabled: map[string]bool{"alice": true},
		codes:   map[string]string{"alice": "123456"},
	}
	m := simpleAuthMiddleware(t, "alice", "the-password", twoFactor)

	rr := post(t, m, url.Values{"code": {"123456"}}, nil)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want a redirect back to the sign-in page", rr.Code)
	}
	// Restart clears whatever was in the cookie on the way, so the sign-in
	// page is reached as it is after a sign-out
	if location := rr.Header().Get("Location"); !strings.HasPrefix(location, "/signin") {
		t.Errorf("location = %q, want the sign-in page", location)
	}
	if twoFactor.checked != 0 {
		t.Error("a code was checked although no password had been given")
	}
}

// A wrong password never reaches the code step, so the page cannot be used to
// find out who has a second factor.
func TestAWrongPasswordNeverAsksForACode(t *testing.T) {
	twoFactor := &fakeTwoFactor{
		enabled: map[string]bool{"alice": true},
		codes:   map[string]string{"alice": "123456"},
	}
	m := simpleAuthMiddleware(t, "alice", "the-password", twoFactor)

	rr := post(t, m, url.Values{"username": {"alice"}, "password": {"wrong"}}, nil)

	body := rr.Body.String()
	if strings.Contains(body, `name="code"`) {
		t.Error("a wrong password was asked for a code")
	}
	if !strings.Contains(body, "Invalid username or password") {
		t.Errorf("the page does not say the password was wrong: %s", body)
	}
}

// The pending half expires: a browser left on the code page overnight is not
// a way in the next morning.
func TestThePendingLoginExpires(t *testing.T) {
	twoFactor := &fakeTwoFactor{
		enabled: map[string]bool{"alice": true},
		codes:   map[string]string{"alice": "123456"},
	}
	m := simpleAuthMiddleware(t, "alice", "the-password", twoFactor)

	first := post(t, m, url.Values{"username": {"alice"}, "password": {"the-password"}}, nil)
	cookies := first.Result().Cookies()

	// the session says how long it is good for; check the promise itself
	session, err := m.runtime.GetSession(withCookies(httptest.NewRequest(http.MethodGet, "/", nil), cookies))
	if err != nil {
		t.Fatal(err)
	}
	if session.Pending == nil {
		t.Fatal("no pending login was stored")
	}
	if session.Identity != nil {
		t.Error("the pending half carries an identity: it is a login after all")
	}
	if !session.Pending.Valid(time.Now()) {
		t.Error("the pending login is not valid right away")
	}
	if session.Pending.Valid(time.Now().Add(time.Hour)) {
		t.Error("the pending login is still valid an hour later")
	}
}

func withCookies(r *http.Request, cookies []*http.Cookie) *http.Request {
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	return r
}

// The second factor is read at every sign-in, so turning it off takes effect
// at once rather than at the next restart.
func TestTurningItOffTakesEffectAtOnce(t *testing.T) {
	twoFactor := &fakeTwoFactor{
		enabled: map[string]bool{"alice": true},
		codes:   map[string]string{"alice": "123456"},
	}
	m := simpleAuthMiddleware(t, "alice", "the-password", twoFactor)

	if signedIn(post(t, m, url.Values{"username": {"alice"}, "password": {"the-password"}}, nil)) {
		t.Fatal("the password alone signed in")
	}

	twoFactor.enabled["alice"] = false

	if !signedIn(post(t, m, url.Values{"username": {"alice"}, "password": {"the-password"}}, nil)) {
		t.Error("the password alone does not sign in after the second factor was turned off")
	}
}

// What the users package keeps and what the sign-in asks have to line up -
// the fake above is only a fake if the real one behaves the same way.
func TestTheRealTwoFactorSatisfiesTheSignIn(t *testing.T) {
	var _ interface {
		Enabled(string) bool
		Check(string, string) bool
	} = (*users.TwoFactor)(nil)
}

package authconfig

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
)

// fakeGithub answers like a GitHub Enterprise Server: the OAuth endpoints at
// the root and the REST API under /api/v3.
type fakeGithub struct {
	server *httptest.Server
	login  string
	id     int64
	name   string
	// memberships by organization, "active" or "pending"
	orgs   map[string]string
	teams  []string
	emails []map[string]any
	// failMemberships makes the membership lookup fail
	failMemberships bool
}

const fakeGithubToken = "gho_test"

func newFakeGithub(t *testing.T) *fakeGithub {
	t.Helper()
	gh := &fakeGithub{login: "octocat", id: 42, name: "Mona Lisa", orgs: map[string]string{}}
	mux := http.NewServeMux()
	gh.server = httptest.NewServer(mux)
	t.Cleanup(gh.server.Close)

	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code") != "test-code" {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"token_type":"bearer"}`, fakeGithubToken)
	})

	api := func(path string, handle func(w http.ResponseWriter, r *http.Request) any) {
		mux.HandleFunc("/api/v3"+path, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+fakeGithubToken {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if body := handle(w, r); body != nil {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(body)
			}
		})
	}
	api("/user", func(http.ResponseWriter, *http.Request) any {
		return map[string]any{"id": gh.id, "login": gh.login, "name": gh.name}
	})
	api("/user/emails", func(http.ResponseWriter, *http.Request) any {
		return gh.emails
	})
	api("/user/memberships/orgs/{org}", func(w http.ResponseWriter, r *http.Request) any {
		if gh.failMemberships {
			http.Error(w, "boom", http.StatusInternalServerError)
			return nil
		}
		// like GitHub, case insensitive
		state, ok := gh.orgs[strings.ToLower(r.PathValue("org"))]
		if !ok {
			http.NotFound(w, r)
			return nil
		}
		return map[string]any{"state": state}
	})
	api("/user/teams", func(_ http.ResponseWriter, r *http.Request) any {
		perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		teams := []map[string]any{}
		for i := (page - 1) * perPage; i < page*perPage && i < len(gh.teams); i++ {
			org, slug, _ := strings.Cut(gh.teams[i], "/")
			teams = append(teams, map[string]any{"slug": slug, "organization": map[string]any{"login": org}})
		}
		return teams
	})
	return gh
}

func (gh *fakeGithub) config() *GithubConfig {
	return &GithubConfig{
		ClientID:     "client",
		ClientSecret: "secret",
		RedirectURL:  "http://wg-access-server.test/callback",
		BaseURL:      gh.server.URL,
	}
}

func newGithubFlow(t *testing.T, config *GithubConfig) (*authruntime.Provider, *authruntime.ProviderRuntime, *mux.Router) {
	t.Helper()
	provider := config.Provider()
	runtime := authruntime.NewProviderRuntime(sessions.NewCookieStore([]byte("test-session-key")))
	router := mux.NewRouter()
	require.NoError(t, provider.RegisterRoutes(router, runtime))
	return provider, runtime, router
}

// signIn runs the whole flow and returns the callback's response and the
// identity it stored, if any.
func signIn(t *testing.T, config *GithubConfig) (*httptest.ResponseRecorder, *authsession.Identity) {
	t.Helper()
	provider, runtime, router := newGithubFlow(t, config)
	state, _, cookies := doLogin(t, provider, runtime)
	rec := doCallback(t, router, state, cookies)

	req := httptest.NewRequest("GET", "http://wg-access-server.test/", nil)
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	if s, err := runtime.GetSession(req); err == nil {
		return rec, s.Identity
	}
	return rec, nil
}

func TestGithubConfigValidation(t *testing.T) {
	valid := func() *GithubConfig {
		return &GithubConfig{ClientID: "id", ClientSecret: "secret", RedirectURL: "https://vpn.example.com/callback", Organizations: []string{"ffmuc"}}
	}
	require.NoError(t, valid().Validate())

	for name, change := range map[string]func(*GithubConfig){
		"no client id":          func(c *GithubConfig) { c.ClientID = "" },
		"anybody may sign in":   func(c *GithubConfig) { c.Organizations = nil },
		"team without org":      func(c *GithubConfig) { c.Teams = []string{"vpn"} },
		"admin team too nested": func(c *GithubConfig) { c.AdminTeams = []string{"ffmuc/a/b"} },
		"base URL without host": func(c *GithubConfig) { c.BaseURL = "github.example.com" },
	} {
		config := valid()
		change(config)
		assert.Error(t, config.Validate(), name)
	}
}

// Unrestricted, the server would hand out VPN access to every GitHub account.
func TestUnrestrictedGithubRefusesToStart(t *testing.T) {
	auth := &AuthConfig{ProviderConfig: ProviderConfig{Github: &GithubConfig{ClientID: "id", ClientSecret: "s", RedirectURL: "https://x/callback"}}}
	err := auth.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth.github")
}

func TestGithubAsksForTheScopesItNeeds(t *testing.T) {
	gh := newFakeGithub(t)
	for _, tc := range []struct {
		configure func(*GithubConfig)
		scope     string
	}{
		{func(c *GithubConfig) { c.Users = []string{"octocat"} }, "user:email"},
		{func(c *GithubConfig) { c.Organizations = []string{"ffmuc"} }, "user:email read:org"},
		{func(c *GithubConfig) { c.Users = []string{"x"}; c.AdminTeams = []string{"ffmuc/admins"} }, "user:email read:org"},
	} {
		config := gh.config()
		tc.configure(config)
		provider, runtime, _ := newGithubFlow(t, config)

		rec := httptest.NewRecorder()
		provider.Invoke(rec, httptest.NewRequest("GET", "http://wg-access-server.test/signin/0", nil), runtime)
		location, err := url.Parse(rec.Header().Get("Location"))
		require.NoError(t, err)

		assert.Equal(t, gh.server.URL+"/login/oauth/authorize", location.Scheme+"://"+location.Host+location.Path)
		assert.Equal(t, "client", location.Query().Get("client_id"))
		assert.Equal(t, tc.scope, location.Query().Get("scope"))
		assert.NotEmpty(t, location.Query().Get("state"))
	}
}

func TestGithubOrganizationMemberSignsIn(t *testing.T) {
	gh := newFakeGithub(t)
	gh.orgs["ffmuc"] = "active"
	gh.emails = []map[string]any{
		{"email": "old@example.com", "primary": false, "verified": true},
		{"email": "mona@example.com", "primary": true, "verified": true},
	}
	config := gh.config()
	config.Organizations = []string{"other", "FFMUC"}

	rec, identity := signIn(t, config)

	require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())
	require.NotNil(t, identity)
	host := strings.TrimPrefix(gh.server.URL, "http://")
	assert.Equal(t, "github@"+host+":42", identity.Subject)
	assert.Equal(t, "GitHub", identity.Provider)
	assert.Equal(t, "Mona Lisa", identity.Name)
	assert.Equal(t, "mona@example.com", identity.Email)
	assert.False(t, identity.Claims.IsAdmin())
}

// An invitation that was not accepted yet is not a membership.
func TestGithubPendingMembershipIsRefused(t *testing.T) {
	gh := newFakeGithub(t)
	gh.orgs["ffmuc"] = "pending"
	config := gh.config()
	config.Organizations = []string{"ffmuc"}

	rec, identity := signIn(t, config)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Nil(t, identity)
}

func TestGithubOutsiderIsRefused(t *testing.T) {
	gh := newFakeGithub(t)
	gh.teams = []string{"ffmuc/other-team"}
	config := gh.config()
	config.Organizations = []string{"ffmuc"}
	config.Teams = []string{"ffmuc/vpn"}
	config.Users = []string{"somebody-else"}

	rec, identity := signIn(t, config)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "not allowed")
	assert.Nil(t, identity)
}

// The admin team is on the second page of a user who is in many teams.
func TestGithubAdminTeamOnALaterPage(t *testing.T) {
	gh := newFakeGithub(t)
	for i := range 150 {
		gh.teams = append(gh.teams, fmt.Sprintf("big/team-%d", i))
	}
	gh.teams = append(gh.teams, "ffmuc/Admins")
	config := gh.config()
	config.Teams = []string{"ffmuc/admins"}
	config.AdminTeams = []string{"ffmuc/admins"}

	rec, identity := signIn(t, config)

	require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())
	require.NotNil(t, identity)
	assert.True(t, identity.Claims.IsAdmin())
}

func TestGithubUsersAreMatchedCaseInsensitively(t *testing.T) {
	gh := newFakeGithub(t)
	gh.name = ""
	config := gh.config()
	config.Users = []string{"OctoCat"}
	config.AdminUsers = []string{"OCTOCAT"}

	rec, identity := signIn(t, config)

	require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())
	require.NotNil(t, identity)
	assert.True(t, identity.Claims.IsAdmin())
	assert.Equal(t, "octocat", identity.Name, "the login stands in for a missing name")
}

// A failing API call must not be read as "no restriction applies".
func TestGithubAPIFailureRefuses(t *testing.T) {
	gh := newFakeGithub(t)
	gh.failMemberships = true
	config := gh.config()
	config.Organizations = []string{"ffmuc"}

	rec, identity := signIn(t, config)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Nil(t, identity)
}

func TestGithubUnverifiedEmailIsNotUsed(t *testing.T) {
	gh := newFakeGithub(t)
	gh.emails = []map[string]any{{"email": "mona@example.com", "primary": true, "verified": false}}
	config := gh.config()
	config.Users = []string{"octocat"}

	_, identity := signIn(t, config)

	require.NotNil(t, identity)
	assert.Empty(t, identity.Email)
}

func TestGithubCallbackChecksTheState(t *testing.T) {
	gh := newFakeGithub(t)
	config := gh.config()
	config.Users = []string{"octocat"}
	provider, runtime, router := newGithubFlow(t, config)
	_, _, cookies := doLogin(t, provider, runtime)

	rec := doCallback(t, router, "forged-state", cookies)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestGithubCancelledSignIn(t *testing.T) {
	gh := newFakeGithub(t)
	config := gh.config()
	config.Users = []string{"octocat"}
	provider, runtime, router := newGithubFlow(t, config)
	state, _, cookies := doLogin(t, provider, runtime)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://wg-access-server.test/callback?state="+url.QueryEscape(state)+"&error=access_denied", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestGithubComSubject(t *testing.T) {
	assert.Equal(t, "github:42", (&GithubConfig{}).subject(42))
}

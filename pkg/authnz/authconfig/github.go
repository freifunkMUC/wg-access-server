package authconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authutil"
)

const GithubAuthProvider = "github"

// GithubConfig signs users in with their GitHub account. GitHub offers
// OAuth2 but no OpenID Connect for this, so it is a provider of its own
// rather than an OIDC configuration.
//
// Anybody can create a GitHub account, so who may sign in has to be
// restricted: by organization, by team or by user.
type GithubConfig struct {
	// Name is shown on the sign-in button. Defaults to "GitHub".
	Name         string `yaml:"name"`
	ClientID     string `yaml:"clientID"`
	ClientSecret string `yaml:"clientSecret"`
	RedirectURL  string `yaml:"redirectURL"`
	// BaseURL of a GitHub Enterprise Server, e.g. https://github.example.com.
	// Empty for github.com.
	BaseURL string `yaml:"baseURL"`

	// Members of any of these organizations may sign in.
	Organizations []string `yaml:"organizations"`
	// Members of any of these teams may sign in, as "organization/team-slug".
	Teams []string `yaml:"teams"`
	// These GitHub users may sign in, by login.
	Users []string `yaml:"users"`

	// Members of these teams are admins, as "organization/team-slug".
	AdminTeams []string `yaml:"adminTeams"`
	// These GitHub users are admins, by login.
	AdminUsers []string `yaml:"adminUsers"`
}

// Validate reports a configuration that would not work, or that would let
// every GitHub user in.
func (c *GithubConfig) Validate() error {
	if c.ClientID == "" || c.ClientSecret == "" || c.RedirectURL == "" {
		return errors.New("clientID, clientSecret and redirectURL are required")
	}
	if _, err := url.Parse(c.RedirectURL); err != nil {
		return errors.Wrapf(err, "redirectURL is not a URL: %s", c.RedirectURL)
	}
	if c.BaseURL != "" {
		if u, err := url.Parse(c.BaseURL); err != nil || u.Scheme == "" || u.Host == "" {
			return errors.Errorf("baseURL is not a URL such as https://github.example.com: %s", c.BaseURL)
		}
	}
	if len(c.Organizations) == 0 && len(c.Teams) == 0 && len(c.Users) == 0 {
		return errors.New("anybody can create a GitHub account - restrict who may sign in with organizations, teams or users")
	}
	for _, team := range slices.Concat(c.Teams, c.AdminTeams) {
		if org, slug, ok := strings.Cut(team, "/"); !ok || org == "" || slug == "" || strings.Contains(slug, "/") {
			return errors.Errorf("team %q is not of the form organization/team-slug", team)
		}
	}
	return nil
}

func (c *GithubConfig) name() string {
	if c.Name == "" {
		return "GitHub"
	}
	return c.Name
}

// endpoints returns where to send the user to sign in, where to exchange the
// code for a token, and where the REST API is.
func (c *GithubConfig) endpoints() (oauth2.Endpoint, string) {
	if c.BaseURL == "" {
		return oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		}, "https://api.github.com"
	}
	base := strings.TrimSuffix(c.BaseURL, "/")
	return oauth2.Endpoint{
		AuthURL:  base + "/login/oauth/authorize",
		TokenURL: base + "/login/oauth/access_token",
	}, base + "/api/v3"
}

// scopes asks for no more than the configuration needs: the email address
// is only shown, and organization and team membership can only be read with
// read:org.
func (c *GithubConfig) scopes() []string {
	scopes := []string{"user:email"}
	if len(c.Organizations) > 0 || len(c.Teams) > 0 || len(c.AdminTeams) > 0 {
		scopes = append(scopes, "read:org")
	}
	return scopes
}

// subject identifies a GitHub user. It is the numeric id rather than the
// login: a login can be changed, and the old one registered by somebody else.
// The prefix keeps it apart from the subjects of other providers - GitLab's
// are numeric ids, too.
func (c *GithubConfig) subject(id int64) string {
	if c.BaseURL == "" {
		return "github:" + strconv.FormatInt(id, 10)
	}
	host := c.BaseURL
	if u, err := url.Parse(c.BaseURL); err == nil {
		host = u.Host
	}
	return "github@" + host + ":" + strconv.FormatInt(id, 10)
}

func (c *GithubConfig) Provider() *authruntime.Provider {
	// ReadConfig has already refused to start with an invalid configuration;
	// this only guards callers that skipped it.
	if err := c.Validate(); err != nil {
		panic(errors.Wrap(err, "invalid GitHub configuration"))
	}

	endpoint, apiURL := c.endpoints()
	oauthConfig := &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
		Scopes:       c.scopes(),
		Endpoint:     endpoint,
	}
	redirectURL, _ := url.Parse(c.RedirectURL)

	return &authruntime.Provider{
		Type: GithubAuthProvider,
		Name: c.name(),
		Invoke: func(w http.ResponseWriter, r *http.Request, runtime *authruntime.ProviderRuntime) {
			state := authutil.RandomString(32)
			if err := runtime.SetSession(w, r, &authsession.AuthSession{State: &state}); err != nil {
				http.Error(w, "No session", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, oauthConfig.AuthCodeURL(state), http.StatusTemporaryRedirect)
		},
		RegisterRoutes: func(router *mux.Router, runtime *authruntime.ProviderRuntime) error {
			router.HandleFunc(redirectURL.Path, c.callbackHandler(runtime, oauthConfig, apiURL))
			return nil
		},
		Branding: authruntime.ProviderBranding{
			Background: "#24292f",
			Color:      "white",
			Icon:       svgDataURL(githubIcon),
		},
	}
}

func (c *GithubConfig) callbackHandler(runtime *authruntime.ProviderRuntime, oauthConfig *oauth2.Config, apiURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := runtime.GetSession(r)
		if err != nil || s.State == nil {
			http.Error(w, "No sign-in in progress - please start again", http.StatusBadRequest)
			return
		}
		// the state ties the answer to the sign-in this browser started (CSRF)
		if r.FormValue("state") != *s.State {
			http.Error(w, "Bad state value", http.StatusBadRequest)
			return
		}
		if reason := r.FormValue("error"); reason != "" {
			logrus.Infof("GitHub sign-in was not completed: %s", reason)
			http.Error(w, "The sign-in with GitHub was not completed", http.StatusForbidden)
			return
		}

		token, err := oauthConfig.Exchange(r.Context(), r.FormValue("code"))
		if err != nil {
			logrus.Error(errors.Wrap(err, "failed to exchange the GitHub authorization code"))
			http.Error(w, "The sign-in with GitHub failed", http.StatusBadGateway)
			return
		}
		api := &githubAPI{client: oauthConfig.Client(r.Context(), token), baseURL: apiURL}

		identity, err := c.identity(r.Context(), api)
		var refused *refusedError
		if errors.As(err, &refused) {
			logrus.Warnf("Refused the GitHub sign-in of '%s' (remote address: %s): %s", refused.login, r.RemoteAddr, refused.reason)
			http.Error(w, "Your GitHub account is not allowed to use this server.", http.StatusForbidden)
			return
		}
		if err != nil {
			logrus.Error(errors.Wrap(err, "failed to read the GitHub account"))
			http.Error(w, "The sign-in with GitHub failed", http.StatusBadGateway)
			return
		}

		if err := runtime.SetSession(w, r, &authsession.AuthSession{Identity: identity}); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		runtime.Done(w, r)
	}
}

type refusedError struct {
	login  string
	reason string
}

func (e *refusedError) Error() string {
	return e.reason
}

// identity reads the GitHub account and decides whether it may sign in.
func (c *GithubConfig) identity(ctx context.Context, api *githubAPI) (*authsession.Identity, error) {
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := api.get(ctx, "/user", &user); err != nil {
		return nil, err
	}
	if user.ID == 0 || user.Login == "" {
		return nil, errors.New("GitHub returned no user")
	}

	var teams []string
	if len(c.Teams) > 0 || len(c.AdminTeams) > 0 {
		var err error
		if teams, err = api.teams(ctx); err != nil {
			return nil, err
		}
	}

	allowed, err := c.allowed(ctx, api, user.Login, teams)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, &refusedError{user.Login, "not in any of the configured organizations, teams or users"}
	}

	identity := &authsession.Identity{
		Provider: c.name(),
		Subject:  c.subject(user.ID),
		Name:     user.Name,
		Email:    api.primaryEmail(ctx),
	}
	if identity.Name == "" {
		identity.Name = user.Login
	}
	if containsFold(c.AdminUsers, user.Login) || intersectsFold(c.AdminTeams, teams) {
		identity.Claims.MakeAdmin()
	}
	return identity, nil
}

func (c *GithubConfig) allowed(ctx context.Context, api *githubAPI, login string, teams []string) (bool, error) {
	if containsFold(c.Users, login) || intersectsFold(c.Teams, teams) {
		return true, nil
	}
	for _, org := range c.Organizations {
		member, err := api.isMember(ctx, org)
		if err != nil {
			return false, err
		}
		if member {
			return true, nil
		}
	}
	return false, nil
}

// githubAPI calls the REST API on behalf of the signed in user.
type githubAPI struct {
	client  *http.Client
	baseURL string
}

// errNotFound is GitHub's answer for a membership that does not exist.
var errNotFound = errors.New("not found")

func (a *githubAPI) get(ctx context.Context, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	res, err := a.client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "GET %s", path)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	if res.StatusCode != http.StatusOK {
		return errors.Errorf("GET %s: %s", path, res.Status)
	}
	return errors.Wrapf(json.NewDecoder(res.Body).Decode(into), "GET %s", path)
}

// isMember reports whether the user is an active member of org. GitHub
// answers 404 for "no", and also for an organization that does not let this
// OAuth app see its members - which cannot be told apart from here.
func (a *githubAPI) isMember(ctx context.Context, org string) (bool, error) {
	var membership struct {
		State string `json:"state"`
	}
	err := a.get(ctx, "/user/memberships/orgs/"+url.PathEscape(org), &membership)
	if errors.Is(err, errNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return membership.State == "active", nil
}

// teams returns the user's teams as "organization/team-slug".
func (a *githubAPI) teams(ctx context.Context) ([]string, error) {
	const perPage = 100
	var all []string
	// ten pages are a thousand teams, which nobody signing in to a VPN has
	for page := 1; page <= 10; page++ {
		var teams []struct {
			Slug         string `json:"slug"`
			Organization struct {
				Login string `json:"login"`
			} `json:"organization"`
		}
		if err := a.get(ctx, fmt.Sprintf("/user/teams?per_page=%d&page=%d", perPage, page), &teams); err != nil {
			return nil, err
		}
		for _, t := range teams {
			all = append(all, t.Organization.Login+"/"+t.Slug)
		}
		if len(teams) < perPage {
			break
		}
	}
	return all, nil
}

// primaryEmail returns the user's primary address if GitHub verified it. It
// is only shown in the web UI, so failing to read it is no reason to refuse
// the sign-in.
func (a *githubAPI) primaryEmail(ctx context.Context) string {
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := a.get(ctx, "/user/emails", &emails); err != nil {
		logrus.Debug(errors.Wrap(err, "failed to read the GitHub email addresses"))
		return ""
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email
		}
	}
	return ""
}

// GitHub logins, organizations and team slugs are case insensitive.
func containsFold(list []string, value string) bool {
	return slices.ContainsFunc(list, func(item string) bool { return strings.EqualFold(item, value) })
}

func intersectsFold(configured []string, actual []string) bool {
	return slices.ContainsFunc(actual, func(item string) bool { return containsFold(configured, item) })
}

package authconfig

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"gopkg.in/Knetic/govaluate.v2"
	"gopkg.in/yaml.v2"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authutil"
)

const OIDCAuthProvider = "oidc"

// OIDCConfig implements an OIDC client using the [Authorization Code Flow]
// [Authorization Code Flow]: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
type OIDCConfig struct {
	Name              string                    `yaml:"name"`
	Issuer            string                    `yaml:"issuer"`
	ClientID          string                    `yaml:"clientID"`
	ClientSecret      string                    `yaml:"clientSecret"`
	Scopes            []string                  `yaml:"scopes"`
	RedirectURL       string                    `yaml:"redirectURL"`
	EmailDomains      []string                  `yaml:"emailDomains"`
	ClaimMapping      map[string]ruleExpression `yaml:"claimMapping"`
	ClaimsFromIDToken bool                      `yaml:"claimsFromIDToken"`
	AccessClaim       string                    `yaml:"accessClaim"`
}

func (c *OIDCConfig) Provider() *authruntime.Provider {
	// The context for the oidc.Provider must be long-lived for verifying ID tokens later-on
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		panic(errors.Wrap(err, "failed to create OIDC provider"))
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: c.ClientID})

	c.Scopes = ensureScopes(c.Scopes, c.EmailDomains)

	oauthConfig := &oauth2.Config{
		RedirectURL:  c.RedirectURL,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Scopes:       c.Scopes,
		Endpoint:     provider.Endpoint(),
	}

	redirectURL, err := url.Parse(c.RedirectURL)
	if err != nil {
		panic(errors.Wrapf(err, "redirect URL is not valid: %s", c.RedirectURL))
	}

	return &authruntime.Provider{
		Type: OIDCAuthProvider,
		Name: c.Name,
		Invoke: func(w http.ResponseWriter, r *http.Request, runtime *authruntime.ProviderRuntime) {
			c.loginHandler(runtime, oauthConfig)(w, r)
		},
		RegisterRoutes: func(router *mux.Router, runtime *authruntime.ProviderRuntime) error {
			router.HandleFunc(redirectURL.Path, c.callbackHandler(runtime, oauthConfig, provider, verifier))
			return nil
		},
	}
}

func (c *OIDCConfig) loginHandler(runtime *authruntime.ProviderRuntime, oauthConfig *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Client prepares an Authentication Request containing the desired request parameters.
		oauthStateString := authutil.RandomString(32)
		oidcNonce := authutil.RandomString(32)
		err := runtime.SetSession(w, r, &authsession.AuthSession{
			State: &oauthStateString,
			Nonce: &oidcNonce,
		})
		if err != nil {
			http.Error(w, "No session", http.StatusUnauthorized)
			return
		}
		// 2. Client sends the request to the Authorization Server.
		authCodeURL := oauthConfig.AuthCodeURL(oauthStateString, oidc.Nonce(oidcNonce))
		http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
	}
}

func (c *OIDCConfig) callbackHandler(runtime *authruntime.ProviderRuntime, oauthConfig *oauth2.Config,
	provider *oidc.Provider, verifier *oidc.IDTokenVerifier) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// 3. Authorization Server Authenticates the End-User.
		// 4. Authorization Server obtains End-User Consent/Authorization.
		// 5. Authorization Server sends the End-User back to the Client with an Authorization Code.

		s, err := runtime.GetSession(r)
		if err != nil {
			http.Error(w, "No session", http.StatusBadRequest)
			return
		}

		// Make sure the returned state matches the one saved in the session cookie to prevent CSRF attacks
		state := r.FormValue("state")
		if s.State == nil {
			http.Error(w, "No state associated with session", http.StatusBadRequest)
			return
		} else if *s.State != state {
			http.Error(w, "Bad state value", http.StatusBadRequest)
			return
		}

		authCode := r.FormValue("code")

		// 6. Client requests a response using the Authorization Code at the Token Endpoint.
		// 7. Client receives a response that contains an ID Token and Access Token in the response body.
		oauth2Token, err := oauthConfig.Exchange(r.Context(), authCode)
		if err != nil {
			panic(errors.Wrap(err, "unable to exchange tokens"))
		}

		// 8. Client validates the ID token and retrieves the End-User's Subject Identifier.
		oidcClaims := make(map[string]interface{})
		if !c.ClaimsFromIDToken {
			// Use the UserInfo endpoint to retrieve the claims
			logrus.Debug("Retrieving claims from UserInfo endpoint")
			info, err := provider.UserInfo(r.Context(), oauthConfig.TokenSource(r.Context(), oauth2Token))
			if err != nil {
				panic(errors.Wrap(err, "unable to get UserInfo"))
			}

			// Dump the claims
			err = info.Claims(&oidcClaims)
			if err != nil {
				panic(errors.Wrap(err, "unable to unmarshal claims from UserInfo JSON"))
			}
		} else {
			// Extract and parse the ID token to retrieve the claims
			logrus.Debug("Retrieving claims from ID Token")
			rawIDToken, ok := oauth2Token.Extra("id_token").(string)
			if !ok {
				panic(errors.New("No id_token field in OAuth2 token"))
			}
			// Parse and verify ID Token payload
			idToken, err := verifier.Verify(r.Context(), rawIDToken)
			if err != nil {
				panic(errors.Wrap(err, "failed to verify ID token"))
			}

			// Verify the nonce in the ID token matches the one stored in the session
			// to prevent replay attacks
			if s.Nonce == nil {
				http.Error(w, "No nonce associated with session", http.StatusBadRequest)
				return
			} else if idToken.Nonce != *s.Nonce {
				http.Error(w, "Bad nonce value in ID token", http.StatusBadRequest)
				return
			}

			// Dump the claims
			err = idToken.Claims(&oidcClaims)
			if err != nil {
				panic(errors.Wrap(err, "unable to unmarshal claims from ID token JSON"))
			}
		}

		email, _ := oidcClaims["email"].(string)
		if len(c.EmailDomains) > 0 {
			verified, stated := emailVerified(oidcClaims)
			if stated && !verified {
				logrus.Warnf("Refusing login of '%s': the identity provider reports the email address as unverified", email)
				http.Error(w, "Email address is not verified", http.StatusForbidden)
				return
			}
			if !stated {
				// Worth saying out loud: the domain restriction is then only
				// as good as whatever the provider does about verification.
				logrus.Warnf("The identity provider did not state whether the email address of '%s' is verified", email)
			}
		}
		if msg, valid := verifyEmailDomain(c.EmailDomains, email); !valid {
			http.Error(w, msg, http.StatusForbidden)
			return
		}

		claims, err := evaluateClaimMapping(c.ClaimMapping, oidcClaims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Build the authnz Identity for the user, they are now considered logged in
		var subject string
		if sub, ok := oidcClaims["sub"].(string); ok {
			subject = sub
		} else {
			panic(errors.New("No 'sub' claim returned from authorization provider"))
		}
		identity := &authsession.Identity{
			Provider: c.Name,
			Subject:  subject,
			Claims:   *claims,
		}
		if name, ok := oidcClaims["name"].(string); ok {
			identity.Name = name
		}
		if email != "" {
			identity.Email = email
		}

		err = runtime.SetSession(w, r, &authsession.AuthSession{
			Identity: identity,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		runtime.Done(w, r)
	}
}

// ensureScopes returns the scopes to request from the provider. Restricting
// access by email domain needs the email claim, and a provider only sends it
// when the email scope was asked for - without it every single login would be
// refused for not having an address.
func ensureScopes(configured []string, emailDomains []string) []string {
	scopes := configured
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID}
	}
	if len(emailDomains) == 0 || slices.Contains(scopes, "email") {
		return scopes
	}

	logrus.Warnf("Adding the 'email' scope: emailDomains is configured, which needs the email claim")
	return append(slices.Clone(scopes), "email")
}

// emailVerified reports whether the provider marked the address as verified,
// and whether it said anything about it at all. Providers send either a bool
// or a string.
func emailVerified(claims map[string]interface{}) (verified bool, stated bool) {
	switch value := claims["email_verified"].(type) {
	case bool:
		return value, true
	case string:
		return strings.EqualFold(value, "true"), true
	}
	return false, false
}

func verifyEmailDomain(allowedDomains []string, email string) (string, bool) {
	if len(allowedDomains) == 0 {
		return "", true
	}

	parsed := strings.Split(email, "@")

	// check we have 2 parts i.e. <user>@<domain>
	if len(parsed) != 2 {
		return "Missing or invalid email address", false
	}

	// match the domain against the list of allowed domains. Domain names are
	// not case sensitive, and providers do hand out addresses as the user
	// typed them.
	for _, domain := range allowedDomains {
		if strings.EqualFold(domain, parsed[1]) {
			return "", true
		}
	}

	return "Email domain not authorized", false
}

// evaluateClaimMapping translates OIDC claims to custom authnz claims.
func evaluateClaimMapping(claimMapping map[string]ruleExpression, oidcClaims map[string]interface{}) (*authsession.Claims, error) {
	claims := &authsession.Claims{}
	for claimName, rule := range claimMapping {
		result, err := rule.Evaluate(oidcClaims)
		if err != nil {
			return nil, err
		}

		// If result is 'false' or an empty string then don't include the Claim
		if val, ok := result.(bool); ok && val {
			claims.Add(claimName, strconv.FormatBool(val))
		} else if val, ok := result.(string); ok && len(val) > 0 {
			claims.Add(claimName, val)
		}
	}
	return claims, nil
}

type ruleExpression struct {
	*govaluate.EvaluableExpression
}

// MarshalYAML will encode a RuleExpression/govalidate into yaml string
func (r ruleExpression) MarshalYAML() (interface{}, error) {
	return yaml.Marshal(r.String())
}

// UnmarshalYAML will decode a RuleExpression/govalidate into yaml string
func (r *ruleExpression) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var ruleStr string
	if err := unmarshal(&ruleStr); err != nil {
		return err
	}
	parsedRule, err := govaluate.NewEvaluableExpression(ruleStr)
	if err != nil {
		return errors.Wrap(err, "unable to process OIDC rule")
	}
	ruleExpression := &ruleExpression{parsedRule}
	*r = *ruleExpression
	return nil
}

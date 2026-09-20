package authconfig

import (
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authruntime"
)

type ProviderConfig struct {
	OIDC   *OIDCConfig       `yaml:"oidc"`
	Gitlab *GitlabConfig     `yaml:"gitlab"`
	Basic  *BasicAuthConfig  `yaml:"basic"`
	Simple *SimpleAuthConfig `yaml:"simple"`
}

type AuthConfig struct {
	SessionStore *SessionStoreConfig `yaml:"sessionStore"`
	// Embed ProviderConfig for backwards compatibility
	ProviderConfig `yaml:",inline"`
	Multiple       map[string]*ProviderConfig `yaml:"multiple"`
}

type SessionStoreConfig struct {
	Secret string `yaml:"secret"`
	// Secure marks the session cookie as Secure, so browsers only send it
	// over HTTPS. It defaults to false because the web UI is also served
	// over plain HTTP on `port` (see cmd/serve), which is the documented
	// setup when TLS is terminated by a reverse proxy in front of
	// wg-access-server. Turn it on whenever the UI is reachable over
	// HTTPS only.
	Secure bool `yaml:"secure"`
	// MaxAge is how long a session stays valid, as a duration such as "24h".
	// The claims of a session - including whether the user is an admin and
	// whether they still have access - are taken from the identity provider
	// when the session is created and are not re-checked afterwards, so this
	// is also how long it takes for access revoked at the provider to take
	// effect. There is no server-side session store to invalidate.
	// Defaults to 720h (30 days).
	MaxAge string `yaml:"maxAge"`
}

func (c *AuthConfig) IsEnabled() bool {
	return c.OIDC != nil || c.Gitlab != nil || c.Basic != nil || c.Simple != nil || len(c.Multiple) > 0
}

func (c *AuthConfig) DesiresSignInPage() bool {
	// Basic auth is the only that truly needs the sign-in button
	if c.Basic != nil {
		return true
	}
	for _, provider := range c.Multiple {
		if provider.Basic != nil {
			return true
		}
	}
	return false
}

func (c *AuthConfig) Providers() []*authruntime.Provider {
	providers := []*authruntime.Provider{}

	// backwards compatible auth fields via embedded ProviderConfig
	if c.OIDC != nil {
		providers = append(providers, c.OIDC.Provider())
	}
	if c.Gitlab != nil {
		providers = append(providers, c.Gitlab.Provider())
	}
	if c.Basic != nil {
		providers = append(providers, c.Basic.Provider())
	}
	if c.Simple != nil {
		providers = append(providers, c.Simple.Provider())
	}

	for name, providerConfig := range c.Multiple {
		if providerConfig.OIDC != nil {
			// Set the name if not already set
			if providerConfig.OIDC.Name == "" {
				providerConfig.OIDC.Name = name
			}
			providers = append(providers, providerConfig.OIDC.Provider())
		}
		if providerConfig.Gitlab != nil {
			providers = append(providers, providerConfig.Gitlab.Provider())
		}
		if providerConfig.Basic != nil {
			providers = append(providers, providerConfig.Basic.Provider())
		}
		if providerConfig.Simple != nil {
			providers = append(providers, providerConfig.Simple.Provider())
		}
	}

	return providers
}

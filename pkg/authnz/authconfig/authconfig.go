package authconfig

import (
	"fmt"
	"sort"
	"strings"

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

// Validate reports a configuration whose providers could be taken for each
// other.
//
// The name is how a user's identity says where it came from: the admin rule
// of the built-in sign-in and the OIDC access claim look it up by name. An
// identity provider named like the built-in sign-in, or two sharing a name,
// would be taken for each other.
func (c *AuthConfig) Validate() error {
	names := c.identityProviderNames()
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		where := names[name]
		sort.Strings(where)
		if name == BasicAuthProvider || name == SimpleAuthProvider {
			return fmt.Errorf("%s: the name %q is taken by the built-in sign-in, give the provider another one", where[0], name)
		}
		if len(where) > 1 {
			return fmt.Errorf("%s share the name %q: their users could not be told apart, give each provider its own", strings.Join(where, " and "), name)
		}
	}
	return nil
}

// identityProviderNames returns where each identity provider is configured,
// by the name its users carry - with the defaults Providers() applies.
func (c *AuthConfig) identityProviderNames() map[string][]string {
	names := map[string][]string{}
	add := func(name, where string) {
		names[name] = append(names[name], where)
	}

	if c.OIDC != nil {
		add(c.OIDC.Name, "auth.oidc")
	}
	if c.Gitlab != nil {
		add(c.Gitlab.Name, "auth.gitlab")
	}
	for key, provider := range c.Multiple {
		if provider == nil {
			continue
		}
		if provider.OIDC != nil {
			name := provider.OIDC.Name
			if name == "" {
				name = key
			}
			add(name, "auth.multiple."+key+".oidc")
		}
		if provider.Gitlab != nil {
			add(provider.Gitlab.Name, "auth.multiple."+key+".gitlab")
		}
	}
	return names
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

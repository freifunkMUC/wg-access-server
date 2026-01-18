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
	Multiple map[string]*ProviderConfig `yaml:"multiple"`
}

type SessionStoreConfig struct {
	Secret string `yaml:"secret"`
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

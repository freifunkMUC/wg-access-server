package authconfig

import (
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authruntime"
)

const GitlabAuthProvider = "gitlab"

type GitlabConfig struct {
	Name         string   `yaml:"name"`
	BaseURL      string   `yaml:"baseURL"`
	ClientID     string   `yaml:"clientID"`
	ClientSecret string   `yaml:"clientSecret"`
	RedirectURL  string   `yaml:"redirectURL"`
	EmailDomains []string `yaml:"emailDomains"`
}

func (c *GitlabConfig) Provider() *authruntime.Provider {
	o := OIDCConfig{
		Name:         c.Name,
		Issuer:       c.BaseURL,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
		// No scopes of our own: the OIDC provider asks for "openid" and adds
		// "email" when emailDomains is configured. Hardcoding "openid" here
		// used to make every login fail with "Missing or invalid email
		// address", because GitLab only returns the address with that scope.
		EmailDomains: c.EmailDomains,
	}
	p := o.Provider()
	p.Type = GitlabAuthProvider
	p.Name = c.Name
	p.Branding = authruntime.ProviderBranding{
		Background: "#fc6d26",
		Color:      "white",
		Icon:       svgDataURL(gitlabIcon),
	}
	return p
}

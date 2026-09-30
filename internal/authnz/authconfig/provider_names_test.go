package authconfig

import (
	"strings"
	"testing"
)

// Identities are told apart by the name of their provider, so an identity
// provider must not be named like the built-in sign-in or like another one.
func TestProviderNamesMustBeDistinct(t *testing.T) {
	tests := map[string]struct {
		config AuthConfig
		want   string
	}{
		"oidc named simple": {
			config: AuthConfig{Multiple: map[string]*ProviderConfig{"simple": {OIDC: &OIDCConfig{}}}},
			want:   "taken by the built-in sign-in",
		},
		"github named basic": {
			config: AuthConfig{ProviderConfig: ProviderConfig{Github: &GithubConfig{Name: "basic", ClientID: "id", ClientSecret: "secret", RedirectURL: "https://vpn.example.com/callback", Users: []string{"alice"}}}},
			want:   "taken by the built-in sign-in",
		},
		"two oidc with one name": {
			config: AuthConfig{
				ProviderConfig: ProviderConfig{OIDC: &OIDCConfig{Name: "Company"}},
				Multiple:       map[string]*ProviderConfig{"other": {OIDC: &OIDCConfig{Name: "Company"}}},
			},
			want: "share the name",
		},
		"gitlab and github defaults": {
			config: AuthConfig{Multiple: map[string]*ProviderConfig{
				"GitHub": {Gitlab: &GitlabConfig{Name: "GitHub"}},
				"gh":     {Github: &GithubConfig{Name: "GitHub", ClientID: "id", ClientSecret: "secret", RedirectURL: "https://vpn.example.com/callback", Users: []string{"alice"}}},
			}},
			want: "share the name",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.config.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() = %v, want an error containing %q", err, tt.want)
			}
		})
	}

	fine := AuthConfig{
		ProviderConfig: ProviderConfig{OIDC: &OIDCConfig{Name: "Company"}, Simple: &SimpleAuthConfig{}},
		Multiple: map[string]*ProviderConfig{
			"partner": {OIDC: &OIDCConfig{}},
			"local":   {Basic: &BasicAuthConfig{}},
		},
	}
	if err := fine.Validate(); err != nil {
		t.Errorf("distinct names were refused: %v", err)
	}
}

package authconfig

import (
	"slices"
	"testing"
)

func TestEnsureScopes(t *testing.T) {
	tests := []struct {
		name         string
		configured   []string
		emailDomains []string
		want         []string
	}{
		{name: "nothing configured", want: []string{"openid"}},
		{
			name:       "configured scopes are kept",
			configured: []string{"openid", "profile"},
			want:       []string{"openid", "profile"},
		},
		{
			// without the scope the provider sends no address and every login
			// would be refused
			name:         "email domains add the email scope",
			emailDomains: []string{"example.com"},
			want:         []string{"openid", "email"},
		},
		{
			name:         "an already configured email scope is not repeated",
			configured:   []string{"openid", "email"},
			emailDomains: []string{"example.com"},
			want:         []string{"openid", "email"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configured := slices.Clone(tt.configured)

			got := ensureScopes(tt.configured, tt.emailDomains)

			if !slices.Equal(got, tt.want) {
				t.Errorf("ensureScopes(%q, %q) = %q, want %q", tt.configured, tt.emailDomains, got, tt.want)
			}
			if !slices.Equal(tt.configured, configured) {
				t.Errorf("the configured scopes were modified: %q, want %q", tt.configured, configured)
			}
		})
	}
}

func TestEmailVerified(t *testing.T) {
	tests := []struct {
		name         string
		claims       map[string]interface{}
		wantVerified bool
		wantStated   bool
	}{
		{name: "bool true", claims: map[string]interface{}{"email_verified": true}, wantVerified: true, wantStated: true},
		{name: "bool false", claims: map[string]interface{}{"email_verified": false}, wantStated: true},
		// some providers send the claim as a string
		{name: "string true", claims: map[string]interface{}{"email_verified": "true"}, wantVerified: true, wantStated: true},
		{name: "string True", claims: map[string]interface{}{"email_verified": "True"}, wantVerified: true, wantStated: true},
		{name: "string false", claims: map[string]interface{}{"email_verified": "false"}, wantStated: true},
		{name: "claim missing", claims: map[string]interface{}{"email": "user@example.com"}},
		{name: "claim of another type", claims: map[string]interface{}{"email_verified": 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verified, stated := emailVerified(tt.claims)
			if verified != tt.wantVerified || stated != tt.wantStated {
				t.Errorf("emailVerified(%v) = (%v, %v), want (%v, %v)", tt.claims, verified, stated, tt.wantVerified, tt.wantStated)
			}
		})
	}
}

func TestVerifyEmailDomain(t *testing.T) {
	tests := []struct {
		name      string
		domains   []string
		email     string
		wantValid bool
	}{
		{name: "no restriction accepts anything", email: "user@example.com", wantValid: true},
		{name: "no restriction accepts a missing address", wantValid: true},
		{name: "allowed domain", domains: []string{"example.com"}, email: "user@example.com", wantValid: true},
		// domain names are not case sensitive
		{name: "domain in a different case", domains: []string{"example.com"}, email: "User@Example.COM", wantValid: true},
		{name: "configured domain in a different case", domains: []string{"Example.com"}, email: "user@example.com", wantValid: true},
		{name: "other domain", domains: []string{"example.com"}, email: "user@evil.com"},
		{name: "missing address", domains: []string{"example.com"}, email: ""},
		{name: "two at signs", domains: []string{"example.com"}, email: "user@evil.com@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, valid := verifyEmailDomain(tt.domains, tt.email)
			if valid != tt.wantValid {
				t.Errorf("verifyEmailDomain(%q, %q) = (%q, %v), want valid = %v", tt.domains, tt.email, msg, valid, tt.wantValid)
			}
		})
	}
}

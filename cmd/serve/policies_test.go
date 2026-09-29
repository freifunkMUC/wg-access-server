package serve

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authconfig"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/config"
)

func authWithPolicyRules(t *testing.T, names ...string) *authconfig.AuthConfig {
	t.Helper()
	rules := make([]string, 0, len(names))
	for _, name := range names {
		rules = append(rules, "      "+name+": \"'x' in groups\"")
	}
	document := "oidc:\n  issuer: https://example.com\n  policyMapping:\n" + strings.Join(rules, "\n") + "\n"
	// the rules parse from YAML, as they do from the configuration file
	document = strings.ReplaceAll(document, "      ", "    ")

	auth := &authconfig.AuthConfig{}
	if err := yaml.Unmarshal([]byte(document), auth); err != nil {
		t.Fatalf("the test configuration is not valid: %v", err)
	}
	return auth
}

// A policy whose networks cannot be parsed, or that nobody can end up in,
// should stop the server at startup - not at the moment somebody signs in.
func TestValidatePolicies(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policies map[string]config.PolicyConfig
		rules    []string
		says     string
	}{
		{
			name:     "a policy that is fine",
			policies: map[string]config.PolicyConfig{"staff": {AllowedIPs: []string{"10.0.0.0/8"}}},
			rules:    []string{"staff"},
		},
		{
			name:     "a policy without networks",
			policies: map[string]config.PolicyConfig{"staff": {}},
			rules:    []string{"staff"},
			says:     "names no networks",
		},
		{
			name:     "a network that is not one",
			policies: map[string]config.PolicyConfig{"staff": {AllowedIPs: []string{"10.0.0.0"}}},
			rules:    []string{"staff"},
			says:     "invalid network",
		},
		{
			// the rule would silently put nobody anywhere
			name:     "a rule for a policy that does not exist",
			policies: map[string]config.PolicyConfig{"staff": {AllowedIPs: []string{"10.0.0.0/8"}}},
			rules:    []string{"staff", "contractors"},
			says:     "not configured under vpn.policies",
		},
		{
			// dead weight, but somebody may be about to write the rule
			name:     "a policy no rule selects",
			policies: map[string]config.PolicyConfig{"staff": {AllowedIPs: []string{"10.0.0.0/8"}}},
			rules:    nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePolicies(tc.policies, authWithPolicyRules(t, tc.rules...))
			if tc.says == "" {
				if err != nil {
					t.Fatalf("the configuration was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("the configuration was accepted")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the message %q does not say what is wrong (%q)", err.Error(), tc.says)
			}
		})
	}
}

// What is stored has to be comparable: two logins that mean the same must
// produce the same value, whatever order the claims arrived in.
func TestPoliciesOf(t *testing.T) {
	identity := &authsession.Identity{}
	for _, policy := range []string{"staff", "contractors", "staff", ""} {
		identity.Claims.Add(authsession.PolicyClaim, policy)
	}
	identity.Claims.Add(authsession.AdminClaim, "true")

	got := policiesOf(identity)
	if want := []string{"contractors", "staff"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("policies = %v, want %v", got, want)
	}

	if policies := policiesOf(&authsession.Identity{}); len(policies) != 0 {
		t.Errorf("policies = %v, want none for a user without claims", policies)
	}
}

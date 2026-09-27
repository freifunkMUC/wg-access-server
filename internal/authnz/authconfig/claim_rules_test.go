package authconfig

import (
	"strconv"
	"testing"

	"github.com/goccy/go-yaml"
)

// TestClaimMappingSyntax covers the expressions an operator writes into
// claimMapping. They come from the configuration file and are evaluated as
// they always were, so the forms the documentation shows have to keep
// working.
func TestClaimMappingSyntax(t *testing.T) {
	claims := map[string]interface{}{
		"group_membership": []interface{}{"wgas", "WireguardAdmins"},
		"email":            "someone@example.com",
		"level":            3.0,
		"active":           true,
	}

	for _, tc := range []struct {
		rule string
		want string // the value the claim ends up with, "" for no claim
	}{
		// what the documentation shows
		{"'WireguardAdmins' in group_membership", "true"},
		{"'WireguardAccess' in group_membership", ""},
		// the other forms the syntax allows
		{"email == 'someone@example.com'", "true"},
		{"email != 'someone@example.com'", ""},
		{"level > 2", "true"},
		{"active && 'wgas' in group_membership", "true"},
		{"email =~ '@example\\.com$'", "true"},
		{"active ? 'yes' : 'no'", "yes"},
	} {
		t.Run(tc.rule, func(t *testing.T) {
			// through YAML, the way it arrives from the configuration file:
			// in double quotes, so the single ones inside stay
			var rule ruleExpression
			if err := yaml.Unmarshal([]byte(strconv.Quote(tc.rule)), &rule); err != nil {
				t.Fatalf("the rule was not accepted: %v", err)
			}

			got, err := evaluateClaimMapping(map[string]ruleExpression{"admin": rule}, claims)
			if err != nil {
				t.Fatalf("evaluating the rule failed: %v", err)
			}
			if tc.want == "" {
				if len(*got) != 0 {
					t.Fatalf("expected no claim, got %v", *got)
				}
				return
			}
			if len(*got) != 1 || (*got)[0].Name != "admin" || (*got)[0].Value != tc.want {
				t.Fatalf("got %v, want admin=%s", *got, tc.want)
			}
		})
	}
}

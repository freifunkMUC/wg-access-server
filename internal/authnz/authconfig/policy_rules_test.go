package authconfig

import (
	"strconv"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
)

func policyRules(t *testing.T, rules map[string]string) map[string]ruleExpression {
	t.Helper()
	parsed := map[string]ruleExpression{}
	for name, rule := range rules {
		var expression ruleExpression
		// through YAML, the way it arrives from the configuration file
		if err := yaml.Unmarshal([]byte(strconv.Quote(rule)), &expression); err != nil {
			t.Fatalf("the rule of policy %s was not accepted: %v", name, err)
		}
		parsed[name] = expression
	}
	return parsed
}

// Which policies somebody is in is decided by a rule per policy, so they can
// be in several at once - that is the difference to the claim mapping, where
// a name can only carry one value.
func TestPolicyMappingPutsAUserInEveryPolicyThatApplies(t *testing.T) {
	claims := map[string]interface{}{
		"group_membership": []interface{}{"Staff", "Contractors"},
		"email":            "someone@example.com",
	}

	got := &authsession.Claims{}
	if err := evaluatePolicyMapping(got, policyRules(t, map[string]string{
		"contractors": "'Contractors' in group_membership",
		"staff":       "'Staff' in group_membership",
		"guests":      "'Guests' in group_membership",
		"by-email":    "email =~ '@example\\.com$'",
	}), claims); err != nil {
		t.Fatal(err)
	}

	// in order, so that what is stored does not depend on how Go walked a map
	want := []string{"by-email", "contractors", "staff"}
	if policies := got.Values(authsession.PolicyClaim); strings.Join(policies, ",") != strings.Join(want, ",") {
		t.Errorf("policies = %v, want %v", policies, want)
	}
}

// A policy is named by the configuration. A rule that returns a string must
// not be able to name one, or a claim of the provider would decide which
// networks somebody reaches.
func TestPolicyMappingIgnoresRulesThatDoNotSayYes(t *testing.T) {
	claims := map[string]interface{}{"group": "anything", "level": 3.0}

	got := &authsession.Claims{}
	if err := evaluatePolicyMapping(got, policyRules(t, map[string]string{
		"a-string": "'contractors'",
		"a-number": "level",
		"false":    "level > 5",
	}), claims); err != nil {
		t.Fatal(err)
	}

	if policies := got.Values(authsession.PolicyClaim); len(policies) != 0 {
		t.Errorf("policies = %v, want none", policies)
	}
}

// A rule that cannot be evaluated is the operator's mistake, and the message
// has to say which policy it was.
func TestPolicyMappingReportsABrokenRule(t *testing.T) {
	got := &authsession.Claims{}
	err := evaluatePolicyMapping(got, policyRules(t, map[string]string{
		"contractors": "'Contractors' in group_membership",
	}), map[string]interface{}{})

	if err == nil {
		t.Fatal("a rule over a claim that is not there was accepted")
	}
	if !strings.Contains(err.Error(), "contractors") {
		t.Errorf("the error does not name the policy: %v", err)
	}
}

// Claims and policies live side by side: the admin claim keeps working when
// policies are configured, and the other way round.
func TestPolicyMappingKeepsTheOtherClaims(t *testing.T) {
	claims := map[string]interface{}{"group_membership": []interface{}{"WireguardAdmins", "Staff"}}

	got, err := evaluateClaimMapping(policyRules(t, map[string]string{
		"admin": "'WireguardAdmins' in group_membership",
	}), claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := evaluatePolicyMapping(got, policyRules(t, map[string]string{
		"staff": "'Staff' in group_membership",
	}), claims); err != nil {
		t.Fatal(err)
	}

	if !got.IsAdmin() {
		t.Error("the admin claim was lost")
	}
	if policies := got.Values(authsession.PolicyClaim); len(policies) != 1 || policies[0] != "staff" {
		t.Errorf("policies = %v, want staff", policies)
	}
}

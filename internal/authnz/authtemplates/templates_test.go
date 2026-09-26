package authtemplates

import (
	"strings"
	"testing"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authruntime"
)

func render(t *testing.T, providers ...*authruntime.Provider) string {
	t.Helper()
	var out strings.Builder
	if err := RenderLoginPage(&out, LoginPage{Title: "Sign in", Providers: providers}); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// A button inside a link is invalid HTML: it takes two presses of Tab per
// provider, and the link's underline shows through the button.
func TestProvidersAreLinksNotButtonsInLinks(t *testing.T) {
	page := render(t, &authruntime.Provider{Type: "oidc", Name: "Keycloak"})
	if !strings.Contains(page, `class="provider"`) || !strings.Contains(page, "Keycloak") {
		t.Fatalf("no provider link in:\n%s", page)
	}
	if strings.Contains(page, "<button") {
		t.Error("the provider is still a button")
	}
}

func TestSimpleAuthIsLabelledForPeople(t *testing.T) {
	page := render(t, &authruntime.Provider{Type: "simple", Name: "simple"})
	if !strings.Contains(page, "Username and password") {
		t.Error("the simple provider is not labelled for people")
	}
}

// Password managers need to recognise the fields.
func TestTheFormWorksWithPasswordManagers(t *testing.T) {
	page := render(t, &authruntime.Provider{Type: "basic", Name: "basic"})
	for _, want := range []string{`autocomplete="username"`, `autocomplete="current-password"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the form lacks %s", want)
		}
	}
	if strings.Contains(page, `autocomplete="off"`) {
		t.Error("the form turns autocompletion off")
	}
}

// The divider separates the providers from the form; with only one of the
// two there is nothing to separate.
func TestDividerOnlyBetweenProvidersAndForm(t *testing.T) {
	both := render(t, &authruntime.Provider{Type: "basic"}, &authruntime.Provider{Type: "oidc", Name: "Keycloak"})
	hr, form, link := strings.Index(both, "<hr>"), strings.Index(both, "<form"), strings.Index(both, `class="provider"`)
	if hr < 0 || link > hr || hr > form {
		t.Errorf("want the providers, the divider, then the form (link %d, hr %d, form %d)", link, hr, form)
	}

	if onlyForm := render(t, &authruntime.Provider{Type: "basic"}); strings.Contains(onlyForm, "<hr>") {
		t.Error("a divider with nothing to divide")
	}
}

// Icons are data: URLs, which html/template would otherwise replace with
// "#ZgotmplZ"; anything that is neither an image nor https is dropped.
func TestProviderIcons(t *testing.T) {
	icon := "data:image/svg+xml;base64,PHN2Zy8+"
	page := render(t, &authruntime.Provider{Type: "gitlab", Name: "GitLab", Branding: authruntime.ProviderBranding{Icon: icon}})
	if !strings.Contains(page, `src="data:image/svg`) || strings.Contains(page, "ZgotmplZ") {
		t.Error("the icon did not make it into the page")
	}

	page = render(t, &authruntime.Provider{Type: "oidc", Name: "x", Branding: authruntime.ProviderBranding{Icon: "javascript:alert(1)"}})
	if strings.Contains(page, "javascript:") {
		t.Error("a javascript: URL made it into the page")
	}
}

func TestSimpleAuthPageLinksBackOnlyWhenThereIsSomewhereToGo(t *testing.T) {
	for _, others := range []bool{true, false} {
		var out strings.Builder
		if err := RenderSimpleAuthPage(&out, SimpleAuthPage{PostURL: "/signin/simpleauth", OtherProviders: others}); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(out.String(), `href="/signin"`); got != others {
			t.Errorf("other providers %v: link back = %v", others, got)
		}
	}
}

// Both sign-in pages carry the footer and an icon of their own: the web UI's
// favicon is behind the sign-in, so a signed out browser cannot load it.
func TestPagesHaveFooterAndIcon(t *testing.T) {
	var simple strings.Builder
	if err := RenderSimpleAuthPage(&simple, SimpleAuthPage{PostURL: "/signin/simpleauth"}); err != nil {
		t.Fatal(err)
	}
	for name, page := range map[string]string{
		"login":  render(t, &authruntime.Provider{Type: "oidc", Name: "Keycloak"}),
		"simple": simple.String(),
	} {
		if !strings.Contains(page, "https://github.com/freifunkMUC/wg-access-server") {
			t.Errorf("%s page: no link to the source", name)
		}
		if !strings.Contains(page, `rel="icon" href="data:image/svg+xml;base64,`) {
			t.Errorf("%s page: no icon", name)
		}
	}
}

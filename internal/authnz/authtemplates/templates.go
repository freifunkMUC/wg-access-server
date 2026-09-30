package authtemplates

import (
	_ "embed"
	"html/template"
	"io"
	"strings"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
)

var (
	//go:embed base.go.html
	base string
	//go:embed login.go.html
	loginPage string
	//go:embed simpleauth.go.html
	simpleAuthPage string
	//go:embed signout.go.html
	signoutPage string
	// PasskeyScript is the sign-in page's passkey button, served as a file
	// so that the pages keep their Content-Security-Policy of script-src
	// 'self'.
	//
	//go:embed passkey.js
	PasskeyScript string
)

// iconURL lets the provider logos through, which are data: URLs that
// html/template would otherwise replace. They are set in code, never taken
// from a request; anything but an image or an https URL is dropped anyway.
func iconURL(url string) template.URL {
	if strings.HasPrefix(url, "data:image/") || strings.HasPrefix(url, "https://") {
		return template.URL(url)
	}
	return ""
}

var (
	baseTemplate       = template.Must(template.New("base").Funcs(template.FuncMap{"iconURL": iconURL}).Parse(base))
	loginPageTemplate  = template.Must(template.Must(baseTemplate.Clone()).Parse(loginPage))
	simpleAuthTemplate = template.Must(template.Must(baseTemplate.Clone()).Parse(simpleAuthPage))
	signoutTemplate    = template.Must(template.Must(baseTemplate.Clone()).Parse(signoutPage))
)

type LoginPage struct {
	Title     string
	Providers []*authruntime.Provider
	Banner    *authsession.Banner
}

func RenderLoginPage(w io.Writer, data LoginPage) error {
	return loginPageTemplate.Execute(w, data)
}

type SimpleAuthPage struct {
	PostURL      string
	ErrorMessage string
	// OtherProviders adds a link back to the other ways to sign in.
	OtherProviders bool
	// AskForCode turns the page into the second step: the password was
	// right, and the code from the authenticator app is what is missing.
	AskForCode bool
	// OfferPasskey adds the passkey button to that step, for somebody who
	// registered one.
	OfferPasskey bool
	// PasskeyURL is where the browser asks what to sign.
	PasskeyURL string
	// PasskeyScriptURL is where the script that does the asking is served.
	PasskeyScriptURL string
	// HasCodes is whether an authenticator app is set up as well. Without
	// one, the passkey is the only way on and the code field would be a
	// field nobody can fill in.
	HasCodes bool
}

func RenderSimpleAuthPage(w io.Writer, data SimpleAuthPage) error {
	return simpleAuthTemplate.Execute(w, data)
}

func RenderSignoutPage(w io.Writer) error {
	return signoutTemplate.Execute(w, nil)
}

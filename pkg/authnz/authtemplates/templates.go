package authtemplates

import (
	_ "embed"
	"html/template"
	"io"
	"strings"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
)

var (
	//go:embed base.go.html
	base string
	//go:embed login.go.html
	loginPage string
	//go:embed simpleauth.go.html
	simpleAuthPage string
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
}

func RenderSimpleAuthPage(w io.Writer, data SimpleAuthPage) error {
	return simpleAuthTemplate.Execute(w, data)
}

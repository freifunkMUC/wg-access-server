package authconfig

import (
	_ "embed"
	"encoding/base64"
)

// The provider logos are part of the page rather than loaded from the
// provider: the Content-Security-Policy only allows images from the server
// itself, and a logo that moves (GitLab's did) leaves a broken image behind.
// They come from Simple Icons (https://simpleicons.org, CC0).

//go:embed icons/gitlab.svg
var gitlabIcon []byte

//go:embed icons/github.svg
var githubIcon []byte

func svgDataURL(svg []byte) string {
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(svg)
}

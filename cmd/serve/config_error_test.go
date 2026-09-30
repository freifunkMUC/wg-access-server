package serve

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/freifunkMUC/wg-access-server/internal/config"
)

// A broken configuration file must be reported without the secrets next to
// the problem.
func TestConfigFileErrorLeavesOutTheFile(t *testing.T) {
	for _, doc := range []string{
		"adminPassword: hunter2-secret\nadminPassword: other-secret\n",
		"adminPassword: hunter2-secret\nport: 80x0\n",
		"auth:\n  sessionStore:\n    secret: hunter2-secret\n   bad: [\n",
		"adminPassword: [hunter2-secret\n",
	} {
		var conf config.AppConfig
		err := yaml.Unmarshal([]byte(doc), &conf)
		if err == nil {
			t.Fatalf("%q was accepted", doc)
		}
		message := configFileError(err).Error()
		if strings.Contains(message, "secret") {
			t.Errorf("the error quotes the file: %s", message)
		}
		if !strings.Contains(message, "[") {
			t.Errorf("the error does not say where the problem is: %s", message)
		}
	}
}

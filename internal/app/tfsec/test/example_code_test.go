package test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func TestExampleCode(t *testing.T) {
	for _, check := range scanner.GetRegisteredRules() {

		t.Run(fmt.Sprintf("Rule explanation for %s", check.ID()), func(t *testing.T) {
			if strings.TrimSpace(check.Documentation.Explanation) == "" {
				t.Fatalf("No explanation found for %s", check.ID())
			}
		})

		t.Run(fmt.Sprintf("Rule impact for %s", check.ID()), func(t *testing.T) {
			if strings.TrimSpace(check.Documentation.Impact) == "" {
				t.Fatalf("No impact found for %s", check.ID())
			}
		})

		t.Run(fmt.Sprintf("Rule resolution for %s", check.ID()), func(t *testing.T) {
			if strings.TrimSpace(check.Documentation.Resolution) == "" {
				t.Fatalf("No resolution found for %s", check.ID())
			}
		})

		t.Run(fmt.Sprintf("Rule bad example(s) for %s", check.ID()), func(t *testing.T) {
			if len(check.Documentation.BadExample) == 0 {
				t.Fatalf("No resolution found for %s", check.ID())
			}
		})

		t.Run(fmt.Sprintf("Rule good example(s) for %s", check.ID()), func(t *testing.T) {
			if len(check.Documentation.GoodExample) == 0 {
				t.Fatalf("No resolution found for %s", check.ID())
			}
		})
	}
}

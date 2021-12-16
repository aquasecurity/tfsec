package test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func TestExampleCode(t *testing.T) {
	for _, rule := range scanner.GetRegisteredRules() {

		t.Run(fmt.Sprintf("Rule explanation for %s", rule.ID()), func(t *testing.T) {
			if strings.TrimSpace(rule.Base.Rule().Explanation) == "" {
				t.Fatalf("No explanation found for %s", rule.ID())
			}
		})

		t.Run(fmt.Sprintf("Rule impact for %s", rule.ID()), func(t *testing.T) {
			if strings.TrimSpace(rule.Base.Rule().Impact) == "" {
				t.Fatalf("No impact found for %s", rule.ID())
			}
		})

		t.Run(fmt.Sprintf("Rule resolution for %s", rule.ID()), func(t *testing.T) {
			if strings.TrimSpace(rule.Base.Rule().Resolution) == "" {
				t.Fatalf("No resolution found for %s", rule.ID())
			}
		})

		t.Run(fmt.Sprintf("Rule bad example(s) for %s", rule.ID()), func(t *testing.T) {
			if len(rule.BadExample) == 0 {
				t.Fatalf("No bad example found for %s", rule.ID())
			}
		})

		t.Run(fmt.Sprintf("Rule good example(s) for %s", rule.ID()), func(t *testing.T) {
			if len(rule.GoodExample) == 0 {
				t.Fatalf("No good example found for %s", rule.ID())
			}
		})
	}
}

func TestBlockTypes(t *testing.T) {
	for _, rule := range scanner.GetRegisteredRules() {
		for _, blockType := range rule.RequiredTypes {
			switch blockType {
			case "resource", "data", "provider", "variable", "module", "locals", "output":
			default:
				t.Errorf("Invalid required block type for rule %s: '%s'", rule.ID(), blockType)
			}
		}
	}
}

func TestBlockLabels(t *testing.T) {
	identifierRegex := regexp.MustCompile(`^[a-zA-Z\-_][a-zA-Z0-9\-_]*$`)
	for _, rule := range scanner.GetRegisteredRules() {
		for _, label := range rule.RequiredLabels {
			if !identifierRegex.MatchString(label) {
				t.Errorf("Invalid required label for rule %s: '%s'", rule.ID(), label)
			}
		}
	}
}

func TestDefSecUsage(t *testing.T) {
	for _, rule := range scanner.GetRegisteredRules() {
		t.Run(rule.ID(), func(t *testing.T) {
			if rule.Base.Rule().AVDID == "" {
				t.Error("Rule is not ready for defsec")
			}
		})
	}
}

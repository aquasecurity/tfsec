package test

import (
	"regexp"
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

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
				t.Errorf("Rule is not ready for defsec: %#v", rule)
			}
		})
	}
}

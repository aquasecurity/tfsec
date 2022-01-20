package test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
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

func TestRulesAgainstExampleCode(t *testing.T) {
	for _, rule := range scanner.GetRegisteredRules() {
		t.Run(rule.Base.Rule().LongID(), func(t *testing.T) {
			t.Run("good examples", func(t *testing.T) {
				for i, example := range rule.Base.Rule().Terraform.GoodExamples {
					t.Run(fmt.Sprintf("example %d", i), func(t *testing.T) {
						results := testutil.ScanHCL(example, t)
						testutil.AssertRuleNotFound(t, rule.ID(), results, "Rule %s was detected in good example #%d", rule.ID(), i)
					})
				}
			})
			t.Run("bad examples", func(t *testing.T) {
				for i, example := range rule.Base.Rule().Terraform.BadExamples {
					t.Run(fmt.Sprintf("example %d", i), func(t *testing.T) {
						results := testutil.ScanHCL(example, t)
						testutil.AssertRuleFound(t, rule.ID(), results, "Rule %s was detected in good example #%d", rule.ID(), i)
					})
				}
			})

		})
	}
}

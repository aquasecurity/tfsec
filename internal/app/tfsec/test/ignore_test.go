package test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/result"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"

	"github.com/stretchr/testify/assert"
)

var exampleRule = rule.Rule{
	LegacyID: "ABC123",
	DefSecCheck: rules.RuleDef{
		Provider:  provider.AWSProvider,
		Service:   "service",
		ShortCode: "abc123",
		Severity:  severity.High,
	},
	RequiredLabels: []string{"bad"},
	CheckTerraform: func(set result.Set, resourceBlock block.Block, _ block.Module) {
		attr := resourceBlock.GetAttribute("secure")
		if attr.IsNil() {
			set.AddResult().
				WithDescription("example problem").
				WithRange(resourceBlock.Range())
		}
		if attr.IsFalse() {
			set.AddResult().
				WithDescription("example problem").
				WithRange(attr.Range())
		}
	},
}

func Test_IgnoreAll(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
resource "bad" "my-rule" {
    secure = false // tfsec:ignore:*
}
`, t)
	assert.Len(t, results, 0)

}

func Test_IgnoreLineAboveTheBlock(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
// tfsec:ignore:*
resource "bad" "my-rule" {
    
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreLineAboveTheLine(t *testing.T) {
	results := testutil.ScanHCL(`

resource "bad" "my-rule" {
	# tfsec:ignore:ABC123
    secure = false
}
`, t)
	assert.Len(t, results, 0)
}
func Test_IgnoreLineOnTheLine(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)
	results := testutil.ScanHCL(`
resource "bad" "my-rule" {
    secure = false # tfsec:ignore:ABC123
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreLineWithCarriageReturn(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(strings.ReplaceAll(`
resource "bad" "my-rule" {
    secure = false # tfsec:ignore:ABC123
}
`, "\n", "\r\n"), t)
	assert.Len(t, results, 0)
}

func Test_IgnoreSpecific(t *testing.T) {

	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	r2 := rule.Rule{
		LegacyID: "DEF456",
		DefSecCheck: rules.RuleDef{
			Provider:  provider.AWSProvider,
			Service:   "service",
			ShortCode: "def456",
			Severity:  severity.High,
		},
		RequiredLabels: []string{"bad"},
		CheckTerraform: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			set.AddResult().
				WithDescription("example problem").
				WithRange(resourceBlock.Range())
		},
	}
	scanner.RegisterCheckRule(r2)
	defer scanner.DeregisterCheckRule(r2)

	results := testutil.ScanHCL(`
	//tfsec:ignore:ABC123
	resource "bad" "my-bad" {} 
	//tfsec:ignore:aws-service-abc123
	resource "bad" "my-bad" {} 
`, t)
	require.Len(t, results, 2)
	assert.Equal(t, results[0].RuleID, "aws-service-def456")
	assert.Equal(t, results[1].LegacyRuleID, "DEF456")

}

func Test_IgnoreWithExpDateIfDateBreachedThenDontIgnore(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
resource "bad" "my-rule" {
    secure = false # tfsec:ignore:ABC123:exp:2000-01-02
}
`, t)
	assert.Len(t, results, 1)
}

func Test_IgnoreWithExpDateIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
resource "bad" "my-rule" {
    secure = false # tfsec:ignore:ABC123:exp:2221-01-02
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreWithExpDateIfDateInvalidThenDropTheIgnore(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
resource "bad" "my-rule" {
   secure = false # tfsec:ignore:ABC123:exp:2221-13-02
}
`, t)
	assert.Len(t, results, 1)
}

func Test_IgnoreAboveResourceBlockWithExpDateIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
#tfsec:ignore:ABC123:exp:2221-01-02
resource "bad" "my-rule" {
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreAboveResourceBlockWithExpDateAndMultipleIgnoresIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
# tfsec:ignore:ABC123:exp:2221-01-02 tfsec:ignore:AWS018
resource "bad" "my-rule" {
	
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreIgnoreWithExpiryAndWorkspaceAndWorkspaceSupplied(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
# tfsec:ignore:ABC123:exp:2221-01-02 #tfsec:ignore:AWS018:ws:testworkspace
resource "bad" "my-rule" {
}
`, t, scanner.OptionWithWorkspaceName("testworkspace"))
	assert.Len(t, results, 0)
}

func Test_IgnoreInline(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(fmt.Sprintf(`
	resource "bad" "sample" {
		  secure = false # tfsec:ignore:%s
	}
	  `, exampleRule.ID()), t)
	assert.Len(t, results, 0)
}

func Test_IgnoreIgnoreWithExpiryAndWorkspaceButWrongWorkspaceSupplied(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
# tfsec:ignore:ABC123:exp:2221-01-02:ws:otherworkspace
resource "bad" "my-rule" {
	
}
`, t, scanner.OptionWithWorkspaceName("testworkspace"))
	assert.Len(t, results, 1)
}

func TestBlockLevelIgnoresForAllRules(t *testing.T) {

	for _, check := range scanner.GetRegisteredRules() {
		for _, badExample := range check.BadExample {

			if strings.TrimSpace(badExample) == "" {
				continue
			}

			results := testutil.ScanHCL(badExample, t)
			badLines := strings.Split(badExample, "\n")

			t.Run(fmt.Sprintf("Test block-level ignore for %s", check.ID()), func(t *testing.T) {
				defer func() {
					if err := recover(); err != nil {
						t.Fatalf("Scan (bad) failed: %s", err)
					}
				}()
				var lines []string
				for i, badLine := range badLines {
					for _, result := range results {
						if result.RuleID != check.ID() {
							continue
						}
						if result.Range().GetStartLine()-1 == i {
							lines = append(lines, fmt.Sprintf("# tfsec:ignore:%s", check.ID()))
						}
					}
					lines = append(lines, badLine)
				}
				withIgnores := strings.Join(lines, "\n")

				results := testutil.ScanHCL(withIgnores, t)
				testutil.AssertCheckCode(t, "", check.ID(), results, "Ignore rule was not effective")

			})

		}
	}
}

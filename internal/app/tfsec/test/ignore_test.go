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

func Test_IgnoreAll(t *testing.T) {

	results := testutil.ScanHCL(`
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
    cidr_blocks = ["0.0.0.0/0"] // tfsec:ignore:*
	description = "testing"
}
`, t)
	assert.Len(t, results, 0)

}

func Test_IgnoreLineAboveTheBlock(t *testing.T) {
	results := testutil.ScanHCL(`
// tfsec:ignore:*
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
    cidr_blocks = ["0.0.0.0/0"] 
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreLineAboveTheLine(t *testing.T) {
	results := testutil.ScanHCL(`

resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
	# tfsec:ignore:AWS006
    cidr_blocks = ["0.0.0.0/0"] 
	description = "test security group rule"
}
`, t)
	assert.Len(t, results, 0)
}
func Test_IgnoreLineOnTheLine(t *testing.T) {
	results := testutil.ScanHCL(`
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
	
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:AWS006
	description = "test security group rule"
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreLineWithCarriageReturn(t *testing.T) {
	results := testutil.ScanHCL(strings.ReplaceAll(`
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:AWS006
	description = "test security group rule"
}
`, "\n", "\r\n"), t)
	assert.Len(t, results, 0)
}

func Test_IgnoreSpecific(t *testing.T) {

	r1 := rule.Rule{
		LegacyID: "ABC123",
		DefSecCheck: rules.RuleDef{
			Provider:  provider.AWSProvider,
			Service:   "service",
			ShortCode: "abc123",
			Severity:  severity.High,
		},
		RequiredLabels: []string{"bad"},
		CheckTerraform: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			set.AddResult().
				WithDescription("example problem").
				WithRange(resourceBlock.Range())
		},
	}
	scanner.RegisterCheckRule(r1)
	defer scanner.DeregisterCheckRule(r1)

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
	results := testutil.ScanHCL(`
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
	
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:AWS006:exp:2000-01-02
	description = "test security group rule"
}
`, t)
	assert.Len(t, results, 1)
}

func Test_IgnoreWithExpDateIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	results := testutil.ScanHCL(`
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
	
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:AWS006:exp:2221-01-02
	description = "test security group rule"
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreWithExpDateIfDateInvalidThenDropTheIgnore(t *testing.T) {
	results := testutil.ScanHCL(`
resource "aws_security_group_rule" "my-rule" {
   type        = "ingress"

   cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:AWS006:exp:2221-13-02
	description = "test security group rule"
}
`, t)
	assert.Len(t, results, 1)
}

func Test_IgnoreAboveResourceBlockWithExpDateIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	results := testutil.ScanHCL(`
#tfsec:ignore:AWS006:exp:2221-01-02
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
	
    cidr_blocks = ["0.0.0.0/0"]
	description = "test security group rule"
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreAboveResourceBlockWithExpDateAndMultipleIgnoresIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	results := testutil.ScanHCL(`
# tfsec:ignore:AWS006:exp:2221-01-02 tfsec:ignore:AWS018
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
	
    cidr_blocks = ["0.0.0.0/0"]
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreIgnoreWithExpiryAndWorkspaceAndWorkspaceSupplied(t *testing.T) {
	results := testutil.ScanHCL(`
# tfsec:ignore:AWS006:exp:2221-01-02 #tfsec:ignore:AWS018:ws:testworkspace
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
	
    cidr_blocks = ["0.0.0.0/0"]
}
`, t, scanner.OptionWithWorkspaceName("testworkspace"))
	assert.Len(t, results, 0)
}

func Test_IgnoreInline(t *testing.T) {
	results := testutil.ScanHCL(`
	resource "aws_instance" "sample" {
		metadata_options {
		  http_tokens = "optional" # tfsec:ignore:aws-ec2-enforce-http-token-imds
		}
	  }
	  `, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreIgnoreWithExpiryAndWorkspaceButWrongWorkspaceSupplied(t *testing.T) {
	results := testutil.ScanHCL(`
# tfsec:ignore:AWS006:exp:2221-01-02 #tfsec:ignore:AWS018:ws:otherworkspace
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
	
    cidr_blocks = ["0.0.0.0/0"]
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

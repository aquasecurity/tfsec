package test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"

	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

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

	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:        "ABC123",
		Provider:        provider.AWSProvider,
		Service:         "service",
		ShortCode:       "abc123",
		RequiredLabels:  []string{"bad"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			set.AddResult().
				WithDescription("example problem")
		},
	})

	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:        "DEF456",
		Provider:        provider.AWSProvider,
		Service:         "service",
		ShortCode:       "def456",
		RequiredLabels:  []string{"bad"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			set.AddResult().
				WithDescription("example problem")
		},
	})

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
		for _, badExample := range check.Documentation.BadExample {

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
						for _, block := range result.Blocks() {
							if block.Range().StartLine-1 == i {
								lines = append(lines, fmt.Sprintf("# tfsec:ignore:%s", check.ID()))
							}
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

func TestInlineIgnoresForAllRules(t *testing.T) {
	for _, check := range scanner.GetRegisteredRules() {
		for _, badExample := range check.Documentation.BadExample {

			if strings.TrimSpace(badExample) == "" {
				continue
			}

			results := testutil.ScanHCL(badExample, t)
			badLines := strings.Split(badExample, "\n")

			testCases := []struct {
				pre  string
				post string
			}{
				{pre: "#", post: ""},
				{pre: "# ", post: ""},
				{pre: "//", post: ""},
				{pre: "// ", post: ""},
				{pre: "/* ", post: "*/"},
				{pre: "/*", post: "*/"},
				{pre: " #", post: ""},
				{pre: " //", post: ""},
				{pre: " /* ", post: "*/"},
			}
			for _, testCase := range testCases {
				t.Run(fmt.Sprintf("Test attribute-level ignore for %s (pre=[%s] post=[%s])", check.ID(), testCase.pre, testCase.post), func(t *testing.T) {
					var required bool
					for _, result := range results {
						if result.IsOnAttribute() {
							required = true
							break
						}
					}
					if !required {
						return
					}
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
							if result.Range().StartLine-1 == i {
								if !result.IsOnAttribute() || strings.Contains(badLine, "<<") {
									lines = append(lines, fmt.Sprintf("%stfsec:ignore:%s%s", testCase.pre, check.ID(), testCase.post))
								} else {
									badLine = fmt.Sprintf("%s%s", badLine, fmt.Sprintf("%s tfsec:ignore:%s %s", testCase.pre, check.ID(), testCase.post))
								}
							}
						}
						lines = append(lines, badLine)
					}
					withIgnores := strings.Join(lines, "\n")

					t.Log(withIgnores)

					results := testutil.ScanHCL(withIgnores, t)
					testutil.AssertCheckCode(t, "", check.ID(), results, "Ignore rule was not effective")
				})
			}
		}
	}
}

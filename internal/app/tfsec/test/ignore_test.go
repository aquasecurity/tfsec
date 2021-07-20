package test

import (
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
func Test_IgnoreSpecific(t *testing.T) {

	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:        "ABC123",
		Provider:        provider.AWSProvider,
		Service:         "service",
		ShortCode:       "abc123",
		RequiredLabels:  []string{"bad"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			set.Add(
				result.New(resourceBlock).WithDescription("example problem").WithRange(resourceBlock.Range()),
			)
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
			set.Add(
				result.New(resourceBlock).WithDescription("example problem").WithRange(resourceBlock.Range()),
			)
		},
	})

	results := testutil.ScanHCL(`
	resource "bad" "my-bad" {} //tfsec:ignore:ABC123
	resource "bad" "my-bad" {} //tfsec:ignore:aws-service-abc123
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

func Test_IgnoreWithExpDateIfDateInvalidThenDontIgnoreTheIgnore(t *testing.T) {
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
# tfsec:ignore:AWS006:exp:2221-01-02
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
# tfsec:ignore:AWS006:exp:2221-01-02 #tfsec:ignore:AWS018
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

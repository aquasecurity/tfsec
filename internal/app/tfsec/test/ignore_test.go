package test

import (
	"testing"

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

	results := scanHCL(`
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
    cidr_blocks = ["0.0.0.0/0"] // tfsec:ignore:*
	description = "testing"
}
`, t)
	assert.Len(t, results, 0)

}

func Test_IgnoreLineAboveTheBlock(t *testing.T) {
	results := scanHCL(`
// tfsec:ignore:*
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
    cidr_blocks = ["0.0.0.0/0"] 
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreLineAboveTheLine(t *testing.T) {
	results := scanHCL(`

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
	results := scanHCL(`
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
		ID:              "ABC123",
		RequiredLabels:  []string{"bad"},
		DefaultSeverity: severity.Error,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			set.Add(
				result.New(resourceBlock).WithDescription("example problem").WithRange(resourceBlock.Range()).WithSeverity(severity.Error),
			)
		},
	})

	scanner.RegisterCheckRule(rule.Rule{
		ID:              "DEF456",
		RequiredLabels:  []string{"bad"},
		DefaultSeverity: severity.Error,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			set.Add(
				result.New(resourceBlock).WithDescription("example problem").WithRange(resourceBlock.Range()).WithSeverity(severity.Error),
			)
		},
	})

	results := scanHCL(`
resource "bad" "my-bad" {} //tfsec:ignore:ABC123
`, t)
	require.Len(t, results, 1)
	assert.Equal(t, results[0].RuleID, "DEF456")

}

func Test_IgnoreWithExpDateIfDateBreachedThenDontIgnore(t *testing.T) {
	results := scanHCL(`
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
	
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:AWS006:exp:2000-01-02
	description = "test security group rule"
}
`, t)
	assert.Len(t, results, 1)
}

func Test_IgnoreWithExpDateIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	results := scanHCL(`
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
	
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:AWS006:exp:2221-01-02
	description = "test security group rule"
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreWithExpDateIfDateInvalidThenDontIgnoreTheIgnore(t *testing.T) {
	results := scanHCL(`
resource "aws_security_group_rule" "my-rule" {
   type        = "ingress"

   cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:AWS006:exp:2221-13-02
	description = "test security group rule"
}
`, t)
	assert.Len(t, results, 1)
}

func Test_IgnoreAboveResourceBlockWithExpDateIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	results := scanHCL(`
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
	results := scanHCL(`
# tfsec:ignore:AWS006:exp:2221-01-02 #tfsec:ignore:AWS018
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
	
    cidr_blocks = ["0.0.0.0/0"]
}
`, t)
	assert.Len(t, results, 0)
}

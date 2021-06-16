package test

import (
	"testing"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/stretchr/testify/require"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/stretchr/testify/assert"
)

func Test_IgnoreAll(t *testing.T) {

	results := scanSource(`
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
    cidr_blocks = ["0.0.0.0/0"] // tfsec:ignore:*
}
`)
	assert.Len(t, results, 0)

}

func Test_IgnoreLineAboveTheBlock(t *testing.T) {
	results := scanSource(`
// tfsec:ignore:*
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
    cidr_blocks = ["0.0.0.0/0"] 
}
`)
	assert.Len(t, results, 0)
}

func Test_IgnoreLineAboveTheLine(t *testing.T) {
	results := scanSource(`

resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
	# tfsec:ignore:AWS006
    cidr_blocks = ["0.0.0.0/0"] 
	description = "test security group rule"
}
`)
	assert.Len(t, results, 0)
}
func Test_IgnoreLineOnTheLine(t *testing.T) {
	results := scanSource(`
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
	
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:AWS006
	description = "test security group rule"
}
`)
	assert.Len(t, results, 0)
}
func Test_IgnoreSpecific(t *testing.T) {

	scanner.RegisterCheckRule(rule.Rule{
		ID:             "ABC123",
		RequiredLabels: []string{"bad"},
		CheckFunc: func(set result.Set, resourceBlock *block.Block, _ *hclcontext.Context) {
			set.Add(
				result.New(resourceBlock).WithDescription("example problem").WithRange(resourceBlock.Range()).WithSeverity(severity.Error),
			)
		},
	})

	scanner.RegisterCheckRule(rule.Rule{
		ID:             "DEF456",
		RequiredLabels: []string{"bad"},
		CheckFunc: func(set result.Set, resourceBlock *block.Block, _ *hclcontext.Context) {
			set.Add(
				result.New(resourceBlock).WithDescription("example problem").WithRange(resourceBlock.Range()).WithSeverity(severity.Error),
			)
		},
	})

	results := scanSource(`
resource "bad" "my-bad" {} //tfsec:ignore:ABC123
`)
	require.Len(t, results, 1)
	assert.Equal(t, results[0].RuleID, "DEF456")

}

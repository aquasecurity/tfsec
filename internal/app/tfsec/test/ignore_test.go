package test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
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

func Test_IgnoreSpecific(t *testing.T) {

	scanner.RegisterCheck(scanner.Check{
		Code:           "ABC123",
		RequiredLabels: []string{"bad"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			return []scanner.Result{
				check.NewResult("example problem", block.Range(), scanner.SeverityError),
			}
		},
	})

	scanner.RegisterCheck(scanner.Check{
		Code:           "DEF456",
		RequiredLabels: []string{"bad"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			return []scanner.Result{
				check.NewResult("example problem", block.Range(), scanner.SeverityError),
			}
		},
	})

	results := scanSource(`
resource "bad" "my-bad" {} //tfsec:ignore:ABC123
`)
	require.Len(t, results, 1)
	assert.Equal(t, results[0].RuleID, scanner.RuleCode("DEF456"))

}

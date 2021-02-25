package test

import (
	"fmt"
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_WildcardMatchingOnRequiredLabels(t *testing.T) {

	tests := []struct {
		input           string
		pattern         string
		expectedFailure bool
	}{
		{
			pattern:         "aws_*",
			input:           `resource "aws_instance" "blah" {}`,
			expectedFailure: true,
		},
		{
			pattern:         "gcp_*",
			input:           `resource "aws_instance" "blah" {}`,
			expectedFailure: false,
		},
		{
			pattern:         "x_aws_*",
			input:           `resource "aws_instance" "blah" {}`,
			expectedFailure: false,
		},
		{
			pattern:         "aws_security_group*",
			input:           `resource "aws_security_group" "blah" {}`,
			expectedFailure: true,
		},
		{
			pattern:         "aws_security_group*",
			input:           `resource "aws_security_group_rule" "blah" {}`,
			expectedFailure: true,
		},
	}

	for i, test := range tests {

		code := scanner.RuleCode(fmt.Sprintf("WILD%d", i))

		scanner.RegisterCheck(scanner.Check{
			Code: code,
			Documentation: scanner.CheckDocumentation{
				Summary: "blah",
			},
			Provider:       "custom",
			RequiredTypes:  []string{"resource"},
			RequiredLabels: []string{test.pattern},
			CheckFunc: func(check *scanner.Check, rootBlock *parser.Block, ctx *scanner.Context) []scanner.Result {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Custom check failed for resource %s.", rootBlock.FullName()),
						rootBlock.Range(),
						scanner.SeverityError,
					),
				}
			},
		})

		results := scanSource(test.input)

		if test.expectedFailure {
			assertCheckCode(t, code, "", results)
		} else {
			assertCheckCode(t, "", code, results)
		}
	}

}

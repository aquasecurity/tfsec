package test

import (
	"fmt"
	"testing"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

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

		code := fmt.Sprintf("WILD%d", i)

		scanner.RegisterCheckRule(rule.Rule{
			ID: code,
			Documentation: rule.RuleDocumentation{
				Summary: "blah",
			},
			Provider:        "custom",
			RequiredTypes:   []string{"resource"},
			RequiredLabels:  []string{test.pattern},
			DefaultSeverity: severity.Error,
			CheckFunc: func(set result.Set, rootBlock block.Block, ctx *hclcontext.Context) {
				set.Add(
					result.New(rootBlock).WithDescription(fmt.Sprintf("Custom check failed for resource %s.", rootBlock.FullName())).
						WithRange(rootBlock.Range()).
						WithSeverity(severity.Error),
				)
			},
		})

		results := scanHCL(test.input, t)

		if test.expectedFailure {
			assertCheckCode(t, code, "", results)
		} else {
			assertCheckCode(t, "", code, results)
		}
	}

}

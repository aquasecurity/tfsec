package test

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
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
			Service:   "service",
			ShortCode: code,
			Documentation: rule.RuleDocumentation{
				Summary: "blah",
			},
			Provider:        "custom",
			RequiredTypes:   []string{"resource"},
			RequiredLabels:  []string{test.pattern},
			DefaultSeverity: severity.High,
			CheckFunc: func(set result.Set, rootBlock block.Block, ctx *hclcontext.Context) {
				set.Add().
					WithDescription(fmt.Sprintf("Custom check failed for resource %s.", rootBlock.FullName()))
			},
		})

		results := testutil.ScanHCL(test.input, t)

		if test.expectedFailure {
			testutil.AssertCheckCode(t, fmt.Sprintf("custom-service-%s", code), "", results)
		} else {
			testutil.AssertCheckCode(t, "", fmt.Sprintf("custom-service-%s", code), results)
		}
	}

}

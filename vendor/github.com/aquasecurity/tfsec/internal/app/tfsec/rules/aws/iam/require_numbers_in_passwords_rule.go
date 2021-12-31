package iam

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/iam"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/zclconf/go-cty/cty"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS041",
		BadExample: []string{`
 resource "aws_iam_account_password_policy" "bad_example" {
 	# ...
 	# require_numbers not set
 	# ...
 }
 `},
		GoodExample: []string{`
 resource "aws_iam_account_password_policy" "good_example" {
 	# ...
 	require_numbers = true
 	# ...
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_iam_account_password_policy"},
		Base:           iam.CheckRequireNumbersInPasswords,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if attr := resourceBlock.GetAttribute("require_numbers"); attr.IsNil() {
				results.Add("Resource does not require a number in the password.", resourceBlock)
			} else if attr.Value().Type() == cty.Bool {
				if attr.Value().False() {
					results.Add("Resource explicitly specifies not requiring at least one number in the password.", attr)
				}
			}
			return results
		},
	})
}

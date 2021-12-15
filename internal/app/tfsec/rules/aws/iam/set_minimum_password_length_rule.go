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
		LegacyID: "AWS039",
		BadExample: []string{`
resource "aws_iam_account_password_policy" "bad_example" {
	# ...
	# minimum_password_length not set
	# ...
}
		`},
		GoodExample: []string{`
resource "aws_iam_account_password_policy" "good_example" {
	minimum_password_length = 14
}
	`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy",
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_iam_account_password_policy"},
		Base:           iam.CheckSetMinimumPasswordLength,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if attr := resourceBlock.GetAttribute("minimum_password_length"); attr.IsNil() {
				results.Add("Resource does not have a minimum password length set.", resourceBlock)
			} else if attr.Value().Type() == cty.Number {
				value, _ := attr.Value().AsBigFloat().Float64()
				if value < 14 {
					results.Add("Resource has a minimum password length which is less than 14 characters.", attr)
				}
			}
			return results
		},
	})
}

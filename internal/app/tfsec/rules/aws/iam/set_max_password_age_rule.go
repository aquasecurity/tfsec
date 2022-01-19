package iam

import (
	"github.com/aquasecurity/defsec/rules/aws/iam"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS038",
		BadExample: []string{`
resource "aws_iam_account_password_policy" "bad_example" {
	# ...
	# max_password_age not set
	# ...
}`},
		GoodExample: []string{`
resource "aws_iam_account_password_policy" "good_example" {
	max_password_age = 90
}`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_iam_account_password_policy"},
		Base:           iam.CheckSetMaxPasswordAge,
	})
}

package iam

import (
	"github.com/aquasecurity/defsec/rules/aws/iam"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
data aws_caller_identity current {}

resource aws_iam_group developers {
  name =  "developers"
}
`},
		GoodExample: []string{`

resource "aws_iam_group" "support" {
  name =  "support"
}

resource aws_iam_group_policy mfa {
   
    group = aws_iam_group.support.name
    policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Action": "ec2:*",
      "Resource": "*",
      "Condition": {
          "Bool": {
              "aws:MultiFactorAuthPresent": ["true"]
          }
      }
    }
  ]
}
EOF

}
`},
		Links: []string{
			"https://registry.terraform.io/modules/terraform-module/enforce-mfa/aws/latest",
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_iam_group"},
		Base:           iam.CheckEnforceMFA,
	})
}

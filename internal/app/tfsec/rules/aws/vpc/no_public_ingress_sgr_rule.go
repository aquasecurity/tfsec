package vpc

import (
	"github.com/aquasecurity/defsec/rules/aws/vpc"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS006",
		BadExample: []string{`
 resource "aws_security_group_rule" "bad_example" {
 	type = "ingress"
 	cidr_blocks = ["0.0.0.0/0"]
 }
 `},
		GoodExample: []string{`
 resource "aws_security_group_rule" "good_example" {
 	type = "ingress"
 	cidr_blocks = ["10.0.0.0/16"]
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule#cidr_blocks",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group_rule"},
		Base:           vpc.CheckNoPublicIngressSgr,
	})
}

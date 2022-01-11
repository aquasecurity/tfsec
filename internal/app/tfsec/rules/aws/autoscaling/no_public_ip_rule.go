package autoscaling

import (
	"github.com/aquasecurity/defsec/rules/aws/autoscaling"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS012",
		BadExample: []string{`
 resource "aws_launch_configuration" "bad_example" {
 	associate_public_ip_address = true
 }
 `},
		GoodExample: []string{`
 resource "aws_launch_configuration" "good_example" {
 	associate_public_ip_address = false
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration#associate_public_ip_address",
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#associate_public_ip_address",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_launch_configuration", "aws_instance"},
		Base:           autoscaling.CheckNoPublicIp,
	})
}

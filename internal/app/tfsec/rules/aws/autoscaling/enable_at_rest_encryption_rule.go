package autoscaling

import (
	"github.com/aquasecurity/defsec/rules/aws/autoscaling"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS014",
		BadExample: []string{`
 resource "aws_launch_configuration" "bad_example" {
 	root_block_device {
 		encrypted = false
 	}
 }
 `},
		GoodExample: []string{`
 resource "aws_launch_configuration" "good_example" {
 	root_block_device {
 		encrypted = true
 	}
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs-ephemeral-and-root-block-devices",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_launch_configuration"},
		Base:           autoscaling.CheckEnableAtRestEncryption,
	})
}

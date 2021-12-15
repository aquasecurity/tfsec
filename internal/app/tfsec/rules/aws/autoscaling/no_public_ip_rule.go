package autoscaling

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/autoscaling"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_launch_configuration", "aws_instance"},
		Base:           autoscaling.CheckNoPublicIp,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("associate_public_ip_address") {
				return
			}

			publicAttr := resourceBlock.GetAttribute("associate_public_ip_address")
			if publicAttr.IsTrue() {
				results.Add("Resource has a public IP address associated.", publicAttr)
			}

			return results
		},
	})
}

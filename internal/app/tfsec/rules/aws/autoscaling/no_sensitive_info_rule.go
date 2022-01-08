package autoscaling

import (
	"github.com/aquasecurity/defsec/rules/aws/autoscaling"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "aws_launch_configuration" "as_conf" {
   name          = "web_config"
   image_id      = data.aws_ami.ubuntu.id
   instance_type = "t2.micro"
   user_data     = <<EOF
 export DATABASE_PASSWORD=\"SomeSortOfPassword\"
 EOF
 }
 `, `
 resource "aws_launch_configuration" "as_conf" {
   name             = "web_config"
   image_id         = data.aws_ami.ubuntu.id
   instance_type    = "t2.micro"
   user_data_base64 = "ZXhwb3J0IERBVEFCQVNFX1BBU1NXT1JEPSJTb21lU29ydE9mUGFzc3dvcmQi"
 }
 `},
		GoodExample: []string{`
 resource "aws_launch_configuration" "as_conf" {
   name          = "web_config"
   image_id      = data.aws_ami.ubuntu.id
   instance_type = "t2.micro"
   user_data     = <<EOF
 export GREETING="Hello there"
 EOF
 }
 `, `
 resource "aws_launch_configuration" "as_conf" {
 	name             = "web_config"
 	image_id         = data.aws_ami.ubuntu.id
 	instance_type    = "t2.micro"
 	user_data_base64 = "ZXhwb3J0IEVESVRPUj12aW1hY3M="
   }
   `,
		},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration#user_data,user_data_base64",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"aws_launch_configuration",
		},
		Base: autoscaling.CheckNoSensitiveInfo,
	})
}

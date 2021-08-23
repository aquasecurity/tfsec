package ec2

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules/aws/ec2"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS062",
		BadExample: []string{`
 resource "aws_instance" "bad_example" {
 
	 ami           = "ami-12345667"
	 instance_type = "t2.small"
 
	 user_data = <<EOF
 export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
 export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
 export AWS_DEFAULT_REGION=us-west-2 
 EOF
 }
 `},
		GoodExample: []string{`
 resource "aws_iam_instance_profile" "good_example" {
		 // ...
 }
 
 resource "aws_instance" "good_example" {
	 ami           = "ami-12345667"
	 instance_type = "t2.small"
 
	 iam_instance_profile = aws_iam_instance_profile.good_profile.arn
 
	 user_data = <<EOF
	 export GREETING=hello
 EOF
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#user_data",
		},
		DefSecCheck: ec2.CheckNoSecretsInUserData,
	})
}

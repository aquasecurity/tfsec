package ec2

import (
	"github.com/aquasecurity/defsec/rules/aws/ec2"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS079",
		BadExample: []string{`
 resource "aws_instance" "bad_example" {
	 ami           = "ami-005e54dee72cc1d00"
	 instance_type = "t2.micro"
 }
 `},
		GoodExample: []string{`
 resource "aws_instance" "good_example" {
	 ami           = "ami-005e54dee72cc1d00"
	 instance_type = "t2.micro"
	 metadata_options {
	 http_tokens = "required"
	 }	
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#metadata-options",
		},
		Base: ec2.CheckIMDSAccessRequiresToken,
	})
}

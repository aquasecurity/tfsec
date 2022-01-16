package vpc

import (
	"github.com/aquasecurity/defsec/rules/aws/vpc"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS018",
		BadExample: []string{`
 resource "aws_security_group" "bad_example" {
   name        = "http"
 
   ingress {
     description = "HTTP from VPC"
     from_port   = 80
     to_port     = 80
     protocol    = "tcp"
     cidr_blocks = [aws_vpc.main.cidr_block]
   }
 }
 `},
		GoodExample: []string{`
 resource "aws_security_group" "good_example" {
   name        = "http"
   description = "Allow inbound HTTP traffic"
 
   ingress {
     description = "HTTP from VPC"
     from_port   = 80
     to_port     = 80
     protocol    = "tcp"
     cidr_blocks = [aws_vpc.main.cidr_block]
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group_rule"},
		Base:           vpc.CheckAddDescriptionToSecurityGroupRule,
	})
}

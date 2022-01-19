package vpc

import (
	"github.com/aquasecurity/defsec/rules/aws/vpc"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS082",
		BadExample: []string{`
 resource "aws_default_vpc" "default" {
 	tags = {
 	  Name = "Default VPC"
 	}
   }
 `},
		GoodExample: []string{`
 # no aws default vpc present
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_vpc",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_default_vpc"},
		Base:           vpc.CheckNoDefaultVpc,
	})
}

package vpc

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/vpc"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_default_vpc"},
		Base:           vpc.CheckNoDefaultVpc,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			results.Add("Resource should not exist", resourceBlock)
			return results
		},
	})
}

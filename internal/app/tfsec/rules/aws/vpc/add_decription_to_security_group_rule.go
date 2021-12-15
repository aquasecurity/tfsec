package vpc

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group", "aws_security_group_rule"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if resourceBlock.MissingChild("description") {
				results.Add("Resource should include a description for auditing purposes.", resourceBlock)
				return
			}

			descriptionAttr := resourceBlock.GetAttribute("description")
			if descriptionAttr.IsEmpty() {
				results.Add("Resource should include a non-empty description for auditing purposes.", descriptionAttr)
			}
			return results
		},
	})
}

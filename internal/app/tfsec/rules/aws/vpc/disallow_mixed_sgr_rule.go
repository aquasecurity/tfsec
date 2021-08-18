package vpc

import (
	"fmt"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Provider:  provider.AWSProvider,
		Service:   "vpc",
		ShortCode: "disallow-mixed-sgr",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensures that usage of security groups with inline rules and security group rule resources are not mixed.",
			Explanation: `
Mixing Terraform standalone security_group_rule resource and security_group resource with inline ingress/egress rules results in rules being overwritten during Terraform apply.
`,
			Impact:      "Security group rules will be overwritten and will result in unintended blocking of network traffic",
			Resolution:  "Either define all of a security group's rules inline, or none of the security group's rules inline",
			BadExample: []string{`
resource "aws_security_group_rule" "bad_example" {
  	security_group_id = aws_security_group.bad_example_sg.id
	type = "ingress"
	cidr_blocks = ["172.31.0.0/16"]
}

resource "aws_security_group" "bad_example_sg" {
	ingress {
		cidr_blocks = ["10.0.0.0/16"]
	}
}
`},
			GoodExample: []string{`
resource "aws_security_group_rule" "good_example" {
  	security_group_id = aws_security_group.good_example_sg.id
	type = "ingress"
	cidr_blocks = ["10.0.0.0/16", "172.31.0.0/16"]
}

resource "aws_security_group" "good_example_sg" {
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group#resource-aws_security_group",
				"https://github.com/hashicorp/terraform/issues/11011#issuecomment-283076580",
			},
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{
			"aws_security_group_rule",
		},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {
			if resourceBlock.HasChild("security_group_id") {
				sgAttr := resourceBlock.GetAttribute("security_group_id")
				referencedBlock, err := module.GetReferencedBlock(sgAttr)
				if err == nil {
					if referencedBlock.HasChild("egress") || referencedBlock.HasChild("ingress") {
						set.AddResult().
							WithDescription(fmt.Sprintf("Mixed usage between '%s' and '%s'", resourceBlock.FullName(), referencedBlock.FullName()))
					}
				} else {
					debug.Log(err.Error())
				}
			}
		},
	})
}

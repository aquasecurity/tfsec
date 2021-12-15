package elbv2

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/elb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/zclconf/go-cty/cty"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS005",
		BadExample: []string{`
 resource "aws_alb" "bad_example" {
 	internal = false
 }
 `},
		GoodExample: []string{`
 resource "aws_alb" "good_example" {
 	internal = true
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_alb", "aws_elb", "aws_lb"},
		Base:           elb.CheckAlbNotPublic,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if resourceBlock.HasChild("load_balancer_type") && resourceBlock.GetAttribute("load_balancer_type").Equals("gateway") {
				return
			}
			if internalAttr := resourceBlock.GetAttribute("internal"); internalAttr.IsNil() {
				results.Add("Resource is exposed publicly.", resourceBlock)
			} else if internalAttr.Type() == cty.Bool && internalAttr.Value().False() {
				results.Add("Resource is exposed publicly.", internalAttr)
			}
			return results
		},
	})
}

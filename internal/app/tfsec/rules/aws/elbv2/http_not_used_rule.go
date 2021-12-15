package elbv2

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/elb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS004",
		BadExample: []string{`
 resource "aws_alb_listener" "bad_example" {
 	protocol = "HTTP"
 }
 `},
		GoodExample: []string{`
 resource "aws_alb_listener" "good_example" {
 	protocol = "HTTPS"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener",
			"https://www.cloudflare.com/en-gb/learning/ssl/why-is-http-not-secure/",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_lb_listener", "aws_alb_listener"},
		Base:           elb.CheckHttpNotUsed,
		CheckTerraform: func(resourceBlock block.Block, module block.Module) (results rules.Results) {

			if checkIfExempt(resourceBlock, module) {
				return
			}

			protocolAttr := resourceBlock.GetAttribute("protocol")
			if protocolAttr.IsNotNil() {
				if protocolAttr.IsResolvable() && (protocolAttr.Equals("HTTPS", block.IgnoreCase) ||
					protocolAttr.Equals("TLS", block.IgnoreCase)) {
					return
				}
				if protocolAttr.IsResolvable() && protocolAttr.Equals("HTTP") {
					// check if this is a redirect to HTTPS - if it is, then no problem
					if redirectProtocolAttr := resourceBlock.GetNestedAttribute("default_action.redirect.protocol"); redirectProtocolAttr.IsNotNil() {
						if redirectProtocolAttr.IsResolvable() && redirectProtocolAttr.Equals("HTTPS") {
							return
						}
					}
				}
				results.Add("Resource uses plain HTTP instead of HTTPS.", protocolAttr)
			} else {
				results.Add("Resource uses plain HTTP instead of HTTPS.", resourceBlock)
			}

			return results
		},
	})
}

func checkIfExempt(resourceBlock block.Block, module block.Module) bool {
	if resourceBlock.HasChild("load_balancer_arn") {
		lbaAttr := resourceBlock.GetAttribute("load_balancer_arn")
		if lbaAttr.IsResourceBlockReference("aws_lb") {
			referencedBlock, err := module.GetReferencedBlock(lbaAttr, resourceBlock)
			if err == nil {
				if referencedBlock.HasChild("load_balancer_type") {
					loadBalancerType := referencedBlock.GetAttribute("load_balancer_type")
					if loadBalancerType.IsAny("gateway", "network") {
						return true
					}
				}
			} else {
				debug.Log(err.Error())
			}
		}
	}
	return false
}

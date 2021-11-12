package vpc

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/cidr"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS049",
		Service:   "vpc",
		ShortCode: "no-public-ingress",
		Documentation: rule.RuleDocumentation{
			Summary:    "An ingress Network ACL rule allows specific ports from /0.",
			Impact:     "The ports are exposed for ingressing data to the internet",
			Resolution: "Set a more restrictive cidr range",
			Explanation: `
Opening up ACLs to the public internet is potentially dangerous. You should restrict access to IP addresses or ranges that explicitly require it where possible.

`,
			BadExample: []string{`
resource "aws_network_acl_rule" "bad_example" {
  egress         = false
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}
`},
			GoodExample: []string{`
resource "aws_network_acl_rule" "good_example" {
  egress         = false
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = "10.0.0.0/16"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule#cidr_block",
				"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_network_acl_rule"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			egressAttr := resourceBlock.GetAttribute("egress")
			actionAttr := resourceBlock.GetAttribute("rule_action")
			protoAttr := resourceBlock.GetAttribute("protocol")

			if egressAttr.IsNotNil() && egressAttr.IsTrue() {
				return
			}

			if actionAttr.IsNotNil() && actionAttr.NotEqual("allow") {
				return
			}

			if cidrBlockAttr := resourceBlock.GetAttribute("cidr_block"); cidrBlockAttr.IsNotNil() {

				if cidr.IsAttributeOpen(cidrBlockAttr) {
					if protoAttr.Equals("all") || protoAttr.Equals("-1") || protoAttr.Equals(-1) {
						return
					} else {
						set.AddResult().
							WithDescription("Resource '%s' defines a Network ACL rule that allows specific ingress ports from anywhere.", resourceBlock.FullName())
					}
				}

			}

			if ipv6CidrBlockAttr := resourceBlock.GetAttribute("ipv6_cidr_block"); ipv6CidrBlockAttr.IsNotNil() {

				if cidr.IsAttributeOpen(ipv6CidrBlockAttr) {
					if protoAttr.Value().AsString() == "all" || protoAttr.Value().AsString() == "-1" {
						return
					} else {
						set.AddResult().
							WithDescription("Resource '%s' defines a Network ACL rule that allows specific ingress ports from anywhere.", resourceBlock.FullName()).
							WithAttribute(ipv6CidrBlockAttr)
					}
				}

			}

		},
	})
}

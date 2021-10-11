package vpc

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS050",
		Service:   "vpc",
		ShortCode: "no-excessive-port-access",
		Documentation: rule.RuleDocumentation{
			Summary:    "An ingress Network ACL rule allows ALL ports.",
			Impact:     "All ports exposed for egressing data",
			Resolution: "Set specific allowed ports",
			Explanation: `
Ensure access to specific required ports is allowed, and nothing else.
`,
			BadExample: []string{`
resource "aws_network_acl_rule" "bad_example" {
  egress         = false
  protocol       = "all"
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
  cidr_block     = "0.0.0.0/0"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule#to_port",
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

			if actionAttr.IsNil() || !actionAttr.IsString() || actionAttr.NotEqual("allow") {
				return
			}

			if cidrBlockAttr := resourceBlock.GetAttribute("cidr_block"); cidrBlockAttr.IsNotNil() {
				if protoAttr.Equals("all") || protoAttr.Equals("-1") || protoAttr.Equals(-1) {
					set.AddResult().
						WithDescription("Resource '%s' defines a fully open ingress Network ACL rule with ALL ports open.", resourceBlock.FullName()).
						WithAttribute(cidrBlockAttr)
				}
			}

			if ipv6CidrBlockAttr := resourceBlock.GetAttribute("ipv6_cidr_block"); ipv6CidrBlockAttr.IsNotNil() {
				if protoAttr.Equals("all") || protoAttr.Equals("-1") || protoAttr.Equals(-1) {
					set.AddResult().
						WithDescription("Resource '%s' defines a fully open ingress Network ACL rule with ALL ports open.", resourceBlock.FullName()).
						WithAttribute(ipv6CidrBlockAttr)
				}
			}

		},
	})
}

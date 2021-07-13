package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const GoogleOpenInboundFirewallRule = "GCP003"
const GoogleOpenInboundFirewallRuleDescription = "An inbound firewall rule allows traffic from /0."
const GoogleOpenInboundFirewallRuleImpact = "The port is exposed for ingress from the internet"
const GoogleOpenInboundFirewallRuleResolution = "Set a more restrictive cidr range"
const GoogleOpenInboundFirewallRuleExplanation = `
Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets and avoid using the <code>/0</code> subnet.
`
const GoogleOpenInboundFirewallRuleBadExample = `
resource "google_compute_firewall" "bad_example" {
	source_ranges = ["0.0.0.0/0"]
}`
const GoogleOpenInboundFirewallRuleGoodExample = `
resource "google_compute_firewall" "good_example" {
	source_ranges = ["1.2.3.4/32"]
}`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: GoogleOpenInboundFirewallRule,
		Documentation: rule.RuleDocumentation{
			Summary:     GoogleOpenInboundFirewallRuleDescription,
			Impact:      GoogleOpenInboundFirewallRuleImpact,
			Resolution:  GoogleOpenInboundFirewallRuleResolution,
			Explanation: GoogleOpenInboundFirewallRuleExplanation,
			BadExample:  GoogleOpenInboundFirewallRuleBadExample,
			GoodExample: GoogleOpenInboundFirewallRuleGoodExample,
			Links: []string{
				"https://cloud.google.com/vpc/docs/using-firewalls",
				"https://www.terraform.io/docs/providers/google/r/compute_firewall.html",
			},
		},
		Provider:        provider.GCPProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_compute_firewall"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if sourceRanges := resourceBlock.GetAttribute("source_ranges"); sourceRanges != nil {
				if isOpenCidr(sourceRanges) {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' defines a fully open inbound firewall rule.", resourceBlock.FullName())).
							WithRange(sourceRanges.Range()),
					)
				}
			}

		},
	})

}

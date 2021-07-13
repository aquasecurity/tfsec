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

const GoogleOpenOutboundFirewallRule = "GCP004"
const GoogleOpenOutboundFirewallRuleDescription = "An outbound firewall rule allows traffic to /0."
const GoogleOpenOutboundFirewallRuleImpact = "The port is exposed for egress to the internet"
const GoogleOpenOutboundFirewallRuleResolution = "Set a more restrictive cidr range"
const GoogleOpenOutboundFirewallRuleExplanation = `
Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets and avoid using the <code>/0</code> subnet.
`
const GoogleOpenOutboundFirewallRuleBadExample = `
resource "google_compute_firewall" "bad_example" {
	destination_ranges = ["0.0.0.0/0"]
}`
const GoogleOpenOutboundFirewallRuleGoodExample = `
resource "google_compute_firewall" "good_example" {
	destination_ranges = ["1.2.3.4/32"]
}`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: GoogleOpenOutboundFirewallRule,
		Documentation: rule.RuleDocumentation{
			Summary:     GoogleOpenOutboundFirewallRuleDescription,
			Impact:      GoogleOpenOutboundFirewallRuleImpact,
			Resolution:  GoogleOpenOutboundFirewallRuleResolution,
			Explanation: GoogleOpenOutboundFirewallRuleExplanation,
			BadExample:  GoogleOpenOutboundFirewallRuleBadExample,
			GoodExample: GoogleOpenOutboundFirewallRuleGoodExample,
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

			if destinationRanges := resourceBlock.GetAttribute("destination_ranges"); destinationRanges != nil {

				if isOpenCidr(destinationRanges) {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' defines a fully open outbound firewall rule.", resourceBlock.FullName())).
							WithRange(destinationRanges.Range()),
					)
				}
			}

		},
	})
}

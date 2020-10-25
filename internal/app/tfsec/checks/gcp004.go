package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// GoogleOpenOutboundFirewallRule See https://github.com/tfsec/tfsec#included-checks for check info
const GoogleOpenOutboundFirewallRule scanner.RuleCode = "GCP004"
const GoogleOpenOutboundFirewallRuleDescription scanner.RuleSummary = "An outbound firewall rule allows traffic to `/0`."
const GoogleOpenOutboundFirewallRuleExplanation = `
Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets and avoid using the <code>/0</code> subnet.
`
const GoogleOpenOutboundFirewallRuleBadExample = `
resource "google_compute_firewall" "my-firewall" {
	destination_ranges = ["0.0.0.0/0"]
}`
const GoogleOpenOutboundFirewallRuleGoodExample = `
resource "google_compute_firewall" "my-firewall" {
	destination_ranges = ["1.2.3.4/32"]
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GoogleOpenOutboundFirewallRule,
		Documentation: scanner.CheckDocumentation{
			Summary:     GoogleOpenOutboundFirewallRuleDescription,
			Explanation: GoogleOpenOutboundFirewallRuleExplanation,
			BadExample:  GoogleOpenOutboundFirewallRuleBadExample,
			GoodExample: GoogleOpenOutboundFirewallRuleGoodExample,
			Links: []string{
				"https://cloud.google.com/vpc/docs/using-firewalls",
				"https://www.terraform.io/docs/providers/google/r/compute_firewall.html",
			},
		},
		Provider:       scanner.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_compute_firewall"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if destinationRanges := block.GetAttribute("destination_ranges"); destinationRanges != nil {

				if isOpenCidr(destinationRanges, check.Provider) {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' defines a fully open outbound firewall rule.", block.FullName()),
							destinationRanges.Range(),
							scanner.SeverityWarning,
						),
					}
				}
			}

			return nil
		},
	})
}

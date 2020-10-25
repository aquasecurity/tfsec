package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// GoogleOpenInboundFirewallRule See https://github.com/tfsec/tfsec#included-checks for check info
const GoogleOpenInboundFirewallRule scanner.RuleCode = "GCP003"
const GoogleOpenInboundFirewallRuleDescription scanner.RuleSummary = "An inbound firewall rule allows traffic from `/0`."
const GoogleOpenInboundFirewallRuleExplanation = `
Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets and avoid using the <code>/0</code> subnet.
`
const GoogleOpenInboundFirewallRuleBadExample = `
resource "google_compute_firewall" "my-firewall" {
	source_ranges = ["0.0.0.0/0"]
}`
const GoogleOpenInboundFirewallRuleGoodExample = `
resource "google_compute_firewall" "my-firewall" {
	source_ranges = ["1.2.3.4/32"]
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GoogleOpenInboundFirewallRule,
		Documentation: scanner.CheckDocumentation{
			Summary:     GoogleOpenInboundFirewallRuleDescription,
			Explanation: GoogleOpenInboundFirewallRuleExplanation,
			BadExample:  GoogleOpenInboundFirewallRuleBadExample,
			GoodExample: GoogleOpenInboundFirewallRuleGoodExample,
			Links: []string{
				"https://cloud.google.com/vpc/docs/using-firewalls",
				"https://www.terraform.io/docs/providers/google/r/compute_firewall.html",
			},
		},
		Provider:       scanner.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_compute_firewall"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if sourceRanges := block.GetAttribute("source_ranges"); sourceRanges != nil {
				if isOpenCidr(sourceRanges, check.Provider) {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' defines a fully open inbound firewall rule.", block.FullName()),
							sourceRanges.Range(),
							scanner.SeverityWarning,
						),
					}
				}
			}

			return nil
		},
	})

}

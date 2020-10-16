package google

import (
	"fmt"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// GoogleOpenInboundFirewallRule See https://github.com/tfsec/tfsec#included-checks for check info
const GoogleOpenInboundFirewallRule scanner.RuleID = "GCP003"
const GoogleOpenInboundFirewallRuleDescription scanner.RuleSummary = "An inbound firewall rule allows traffic from `/0`."
const GoogleOpenInboundFirewallRuleExplanation = `

`
const GoogleOpenInboundFirewallRuleBadExample = `

`
const GoogleOpenInboundFirewallRuleGoodExample = `

`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GoogleOpenInboundFirewallRule,
		Documentation: scanner.CheckDocumentation{
			Summary:     GoogleOpenInboundFirewallRuleDescription,
			Explanation: GoogleOpenInboundFirewallRuleExplanation,
			BadExample:  GoogleOpenInboundFirewallRuleBadExample,
			GoodExample: GoogleOpenInboundFirewallRuleGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_compute_firewall"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if sourceRanges := block.GetAttribute("source_ranges"); sourceRanges != nil {

				if sourceRanges.Value().LengthInt() == 0 {
					return nil
				}

				for _, cidr := range sourceRanges.Value().AsValueSlice() {
					if strings.HasSuffix(cidr.AsString(), "/0") {
						return []scanner.Result{
							check.NewResult(
								fmt.Sprintf("Resource '%s' defines a fully open inbound firewall rule.", block.Name()),
								sourceRanges.Range(),
								scanner.SeverityWarning,
							),
						}
					}
				}

			}

			return nil
		},
	})

}

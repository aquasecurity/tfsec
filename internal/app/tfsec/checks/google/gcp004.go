package google

import (
	"fmt"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// GoogleOpenOutboundFirewallRule See https://github.com/tfsec/tfsec#included-checks for check info
const GoogleOpenOutboundFirewallRule scanner.RuleID = "GCP004"
const GoogleOpenOutboundFirewallRuleDescription scanner.RuleSummary = "An outbound firewall rule allows traffic to `/0`."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GoogleOpenOutboundFirewallRule,
		Documentation: scanner.CheckDocumentation{
			Summary: GoogleOpenOutboundFirewallRuleDescription,
		},
		Provider:       scanner.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_compute_firewall"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if destinationRanges := block.GetAttribute("destination_ranges"); destinationRanges != nil {

				if destinationRanges.Value().LengthInt() == 0 {
					return nil
				}

				for _, cidr := range destinationRanges.Value().AsValueSlice() {
					if strings.HasSuffix(cidr.AsString(), "/0") {
						return []scanner.Result{
							check.NewResult(
								fmt.Sprintf("Resource '%s' defines a fully open outbound firewall rule.", block.Name()),
								destinationRanges.Range(),
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

package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const OCIComputeIpReservation scanner.RuleCode = "OCI001"
const OCIComputeIpReservationDescription scanner.RuleSummary = "Compute instance requests an IP reservation from a public pool"
const OCIComputeIpReservationImpact = "The compute instance has the ability to be reached from outside"
const OCIComputeIpReservationResolution = "Reconsider the use of an public IP"
const OCIComputeIpReservationExplanation = `
Compute instance requests an IP reservation from a public pool

The compute instance has the ability to be reached from outside, you might want to sonder the use of a non public IP.
`
const OCIComputeIpReservationBadExample = `
resource "opc_compute_ip_address_reservation" "my-ip-address" {
	name            = "my-ip-address"
	ip_address_pool = "public-ippool"
  }
`
const OCIComputeIpReservationGoodExample = `
resource "opc_compute_ip_address_reservation" "my-ip-address" {
	name            = "my-ip-address"
	ip_address_pool = "cloud-ippool"
  }
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: OCIComputeIpReservation,
		Documentation: scanner.CheckDocumentation{
			Summary:     OCIComputeIpReservationDescription,
			Explanation: OCIComputeIpReservationExplanation,
			Impact:      OCIComputeIpReservationImpact,
			Resolution:  OCIComputeIpReservationResolution,
			BadExample:  OCIComputeIpReservationBadExample,
			GoodExample: OCIComputeIpReservationGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/opc/latest/docs/resources/opc_compute_ip_address_reservation",
				"https://registry.terraform.io/providers/hashicorp/opc/latest/docs/resources/opc_compute_instance",
			},
		},
		Provider:       scanner.OracleProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"opc_compute_ip_address_reservation"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if attr := block.GetAttribute("ip_address_pool"); attr != nil {
				if attr.IsAny("public-ippool") {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' is using an IP from a public IP pool", block.FullName()),
							attr.Range(),
							attr,
							scanner.SeverityWarning,
						),
					}
				}
			}
			return nil
		},
	})
}

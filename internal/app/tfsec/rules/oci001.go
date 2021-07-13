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

const OCIComputeIpReservation = "OCI001"
const OCIComputeIpReservationDescription = "Compute instance requests an IP reservation from a public pool"
const OCIComputeIpReservationImpact = "The compute instance has the ability to be reached from outside"
const OCIComputeIpReservationResolution = "Reconsider the use of an public IP"
const OCIComputeIpReservationExplanation = `
Compute instance requests an IP reservation from a public pool

The compute instance has the ability to be reached from outside, you might want to sonder the use of a non public IP.
`
const OCIComputeIpReservationBadExample = `
resource "opc_compute_ip_address_reservation" "bad_example" {
	name            = "my-ip-address"
	ip_address_pool = "public-ippool"
  }
`
const OCIComputeIpReservationGoodExample = `
resource "opc_compute_ip_address_reservation" "good_example" {
	name            = "my-ip-address"
	ip_address_pool = "cloud-ippool"
  }
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: OCIComputeIpReservation,
		Documentation: rule.RuleDocumentation{
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
		Provider:        provider.OracleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"opc_compute_ip_address_reservation"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			if attr := resourceBlock.GetAttribute("ip_address_pool"); attr != nil {
				if attr.Equals("public-ippool") {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' is using an IP from a public IP pool", resourceBlock.FullName())).
							WithRange(attr.Range()).
							WithAttributeAnnotation(attr),
					)
				}
			}
		},
	})
}

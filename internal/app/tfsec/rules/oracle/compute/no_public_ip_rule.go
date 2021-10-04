package compute

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
		LegacyID:  "OCI001",
		Service:   "compute",
		ShortCode: "no-public-ip",
		Documentation: rule.RuleDocumentation{
			Summary: "Compute instance requests an IP reservation from a public pool",
			Explanation: `
Compute instance requests an IP reservation from a public pool

The compute instance has the ability to be reached from outside, you might want to sonder the use of a non public IP.
`,
			Impact:     "The compute instance has the ability to be reached from outside",
			Resolution: "Reconsider the use of an public IP",
			BadExample: []string{`
resource "opc_compute_ip_address_reservation" "bad_example" {
	name            = "my-ip-address"
	ip_address_pool = "public-ippool"
  }
`},
			GoodExample: []string{`
resource "opc_compute_ip_address_reservation" "good_example" {
	name            = "my-ip-address"
	ip_address_pool = "cloud-ippool"
  }
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/opc/latest/docs/resources/opc_compute_ip_address_reservation",
				"https://registry.terraform.io/providers/hashicorp/opc/latest/docs/resources/opc_compute_instance",
			},
		},
		Provider:        provider.OracleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"opc_compute_ip_address_reservation"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if attr := resourceBlock.GetAttribute("ip_address_pool"); attr.Equals("public-ippool") {
				set.AddResult().
					WithDescription("Resource '%s' is using an IP from a public IP pool", resourceBlock.FullName()).
					WithAttribute(attr)
			}
		},
	})
}

package securitycenter

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
		Service:   "security-center",
		ShortCode: "enable-standard-subscription",
		Documentation: rule.RuleDocumentation{
			Summary: "Enable the standard security center subscription tier",
			Explanation: `To benefit from Azure Defender you should use the Standard subscription tier.
			
			Enabling Azure Defender extends the capabilities of the free mode to workloads running in private and other public clouds, providing unified security management and threat protection across your hybrid cloud workloads.
			`,
			Impact:     "Using free subscription does not enable Azure Defender for the resource type",
			Resolution: "Enable standard subscription tier to benefit from Azure Defender",
			BadExample: []string{`
resource "azurerm_security_center_subscription_pricing" "bad_example" {
  tier          = "Free"
  resource_type = "VirtualMachines"
}
`},
			GoodExample: []string{`
resource "azurerm_security_center_subscription_pricing" "good_example" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#tier",
				"https://docs.microsoft.com/en-us/azure/security-center/security-center-pricing",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_security_center_subscription_pricing"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("tier") {
				return
			}

			tierAttr := resourceBlock.GetAttribute("tier")
			if tierAttr.Equals("Free", block.IgnoreCase) {
				set.AddResult().
					WithDescription("Resource '%s' sets security center subscription type to free.", resourceBlock.FullName()).
					WithAttribute(tierAttr)
			}
		},
	})
}

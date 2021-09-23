package securitycenter

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
		ShortCode: "defender-on-keyvault",
		Documentation: rule.RuleDocumentation{
			Summary: "Ensure Azure Defender is set to On for key vaults",
			Explanation: `Azure Defender is a cloud workload protection service that utilizes and agent-based deployment to analyze signals from Azure network fabric and the service control plane, to detect threats across all Azure resources. It can also analyze non-Azure resources, utilizing Azure Arc, including those on-premises and in both AWS and GCP (once they've been onboarded).
			Azure Defender detects unusual and potentially harmful attempts to access or exploit Key Vault accounts. Resource Manager-based Azure Container Registry registries and provide deeper visibility image vulnerabilities.`,
			Impact:     "Azure Defender detects unusual and potentially harmful attempts to access or exploit Key Vault accounts.",
			Resolution: "Enable KeyVaults in Azure Defender",
			BadExample: []string{`
resource "azurerm_security_center_subscription_pricing" "bad_example" {
  tier          = "Free"
  resource_type = "VirtualMachines"
}
`},
			GoodExample: []string{`
resource "azurerm_security_center_subscription_pricing" "good_example" {
  tier          = "Standard"
  resource_type = "VirtualMachines,KeyVaults"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#resource_type",
				"https://docs.microsoft.com/en-us/azure/security-center/defender-for-key-vault-introduction",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_security_center_subscription_pricing"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("resource_type") {
				return
			}

			resourceTypeAttr := resourceBlock.GetAttribute("resource_type")
			if !resourceTypeAttr.Contains("KeyVaults", block.IgnoreCase) {
				set.AddResult().
					WithDescription("Resource '%s' does not contain KeyVaults", resourceBlock.FullName()).
					WithAttribute(resourceTypeAttr)
			}

		},
	})
}

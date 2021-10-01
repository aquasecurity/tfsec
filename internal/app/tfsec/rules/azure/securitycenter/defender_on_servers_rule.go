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
		ShortCode: "defender-on-servers",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure Azure Defender is set to On for Servers",
			Explanation: `Azure Defender is a cloud workload protection service that utilizes and agent-based deployment to analyze signals from Azure network fabric and the service control plane, to detect threats across all Azure resources. It can also analyze non-Azure resources, utilizing Azure Arc, including those on-premises and in both AWS and GCP (once they've been onboarded).`,
			Impact:      "Azure Defender for servers adds threat detection and advanced defenses for Windows and Linux machines.",
			Resolution:  "Enable VirtualMachines in Azure Defender",
			BadExample: []string{`
resource "azurerm_security_center_subscription_pricing" "bad_example" {
  tier          = "Free"
  resource_type = "AppServices"
}
`},
			GoodExample: []string{`
resource "azurerm_security_center_subscription_pricing" "good_example" {
  tier          = "Standard"
  resource_type = "AppServices,VirtualMachines"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#resource_type",
				"https://docs.microsoft.com/en-us/azure/security-center/defender-for-servers-introduction",
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
			if !resourceTypeAttr.Contains("VirtualMachines", block.IgnoreCase) {
				set.AddResult().
					WithDescription("Resource '%s' does not contain VirtualMachines", resourceBlock.FullName()).
					WithAttribute(resourceTypeAttr)
			}
		},
	})
}

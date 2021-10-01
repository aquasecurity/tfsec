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
		ShortCode: "defender-on-sql-servers-vms",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure Azure Defender is set to On for Sql Server on Machines",
			Explanation: `Azure Defender is a cloud workload protection service that utilizes and agent-based deployment to analyze signals from Azure network fabric and the service control plane, to detect threats across all Azure resources. It can also analyze non-Azure resources, utilizing Azure Arc, including those on-premises and in both AWS and GCP (once they've been onboarded).`,
			Impact:      "Azure Defender for SQL servers on machines extends the protections for your Azure-native SQL Servers to fully support hybrid environments and protect SQL servers (all supported version) hosted in Azure.",
			Resolution:  "Enable ContainerRegistry in Azure Defender",
			BadExample: []string{`
resource "azurerm_security_center_subscription_pricing" "bad_example" {
  tier          = "Free"
  resource_type = "VirtualMachines"
}
`},
			GoodExample: []string{`
resource "azurerm_security_center_subscription_pricing" "good_example" {
  tier          = "Standard"
  resource_type = "VirtualMachines,SqlServerVirtualMachines"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#resource_type",
				"https://docs.microsoft.com/en-us/azure/security-center/defender-for-sql-usage",
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
			if !resourceTypeAttr.Contains("SqlServerVirtualMachines", block.IgnoreCase) {
				set.AddResult().
					WithDescription("Resource '%s' does not contain SqlServerVirtualMachines", resourceBlock.FullName()).
					WithAttribute(resourceTypeAttr)
			}
		},
	})
}

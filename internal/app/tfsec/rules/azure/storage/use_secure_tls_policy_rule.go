package storage

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/azure/storage"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU015",
		BadExample: []string{`
 resource "azurerm_storage_account" "bad_example" {
   name                     = "storageaccountname"
   resource_group_name      = azurerm_resource_group.example.name
   location                 = azurerm_resource_group.example.location
 }
 `},
		GoodExample: []string{`
 resource "azurerm_storage_account" "good_example" {
   name                     = "storageaccountname"
   resource_group_name      = azurerm_resource_group.example.name
   location                 = azurerm_resource_group.example.location
   min_tls_version          = "TLS1_2"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#min_tls_version",
			"https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_storage_account"},
		Base:           storage.CheckUseSecureTlsPolicy,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("min_tls_version") {
				results.Add("Resource should have the min tls version set to TLS1_2 .", resourceBlock)
				return
			}

			minTlsAttr := resourceBlock.GetAttribute("min_tls_version")
			if minTlsAttr.IsNone("TLS1_2") {
				results.Add("Resource should have the min tls version set to TLS1_2 .", minTlsAttr)
			}
			return results
		},
	})
}

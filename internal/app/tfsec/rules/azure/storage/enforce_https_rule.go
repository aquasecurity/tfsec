package storage

import (
	"github.com/aquasecurity/defsec/rules/azure/storage"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU014",
		BadExample: []string{`
 resource "azurerm_storage_account" "bad_example" {
   name                      = "storageaccountname"
   resource_group_name       = azurerm_resource_group.example.name
   location                  = azurerm_resource_group.example.location
   account_tier              = "Standard"
   account_replication_type  = "GRS"
   enable_https_traffic_only = false
 }
 `},
		GoodExample: []string{`
 resource "azurerm_storage_account" "good_example" {
   name                      = "storageaccountname"
   resource_group_name       = azurerm_resource_group.example.name
   location                  = azurerm_resource_group.example.location
   account_tier              = "Standard"
   account_replication_type  = "GRS"
   enable_https_traffic_only = true
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#enable_https_traffic_only",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_storage_account"},
		Base:           storage.CheckEnforceHttps,
	})
}

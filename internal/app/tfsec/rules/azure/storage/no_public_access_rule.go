package storage

import (
	"github.com/aquasecurity/defsec/rules/azure/storage"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU011",
		BadExample: []string{`
 resource "azurerm_storage_account" "example" {
	name                     = "examplestoraccount"
 }

 resource "azurerm_storage_container" "bad_example" {
 	name                  = "terraform-container-storage"
	storage_account_name  = azurerm_storage_account.example.name
 	container_access_type = "blob"
 }
 `},
		GoodExample: []string{`
 resource "azurerm_storage_account" "example" {
	name                     = "examplestoraccount"
 }

 resource "azurerm_storage_container" "good_example" {
 	name                  = "terraform-container-storage"
	storage_account_name  = azurerm_storage_account.example.name
 	container_access_type = "private"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_container",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_storage_container"},
		Base:           storage.CheckNoPublicAccess,
	})
}

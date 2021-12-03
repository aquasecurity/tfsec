package storage

// ATTENTION!
// This rule was autogenerated!
// Before making changes, consider updating the generator.

// generator-locked
import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "storage",
		ShortCode: "delete-retention-policy",
		Documentation: rule.RuleDocumentation{
			Summary:     "Specifies the number of days that the blob should be retained if blob soft delete enable",
			Explanation: "If you enable blob soft delete. Blob soft delete protects an individual blob and its versions, snapshots, and metadata from accidental deletes or overwrites by maintaining the deleted data in the system for a specified period of time. During the retention period, you can restore the blob to its state at deletion. After the retention period has expired, the blob is permanently deleted.",
			Impact:      "The blob will permanently deleted if you don't enable blob soft delete.",
			Resolution:  "Provide blob Delete Retention Policy in blob properties",
			BadExample: []string{`
			resource "azurerm_resource_group" "example" {
				name     = "example-resources"
				location = "West Europe"
			  }
			  
			  resource "azurerm_virtual_network" "example" {
				name                = "virtnetname"
				address_space       = ["10.0.0.0/16"]
				location            = azurerm_resource_group.example.location
				resource_group_name = azurerm_resource_group.example.name
			  }
			  
			  resource "azurerm_subnet" "example" {
				name                 = "subnetname"
				resource_group_name  = azurerm_resource_group.example.name
				virtual_network_name = azurerm_virtual_network.example.name
				address_prefixes     = ["10.0.2.0/24"]
				service_endpoints    = ["Microsoft.Sql", "Microsoft.Storage"]
			  }
			  
			  resource "azurerm_storage_account" "example" {
				name                = "storageaccountname"
				resource_group_name = azurerm_resource_group.example.name
			  
				location                 = azurerm_resource_group.example.location
				account_tier             = "Standard"
				account_replication_type = "LRS"
				min_tls_version          = "TLS1_2"
			  
				network_rules {
				  default_action             = "Deny"
				  ip_rules                   = ["100.0.0.1"]
				  virtual_network_subnet_ids = [azurerm_subnet.example.id]
				}
			  
				tags = {
				  environment = "staging"
				}
				blob_properties {
				}  
			  }`,
				`resource "azurerm_resource_group" "example" {
				name     = "example-resources"
				location = "West Europe"
			  }
			  
			  resource "azurerm_virtual_network" "example" {
				name                = "virtnetname"
				address_space       = ["10.0.0.0/16"]
				location            = azurerm_resource_group.example.location
				resource_group_name = azurerm_resource_group.example.name
			  }
			  
			  resource "azurerm_subnet" "example" {
				name                 = "subnetname"
				resource_group_name  = azurerm_resource_group.example.name
				virtual_network_name = azurerm_virtual_network.example.name
				address_prefixes     = ["10.0.2.0/24"]
				service_endpoints    = ["Microsoft.Sql", "Microsoft.Storage"]
			  }
			  
			  resource "azurerm_storage_account" "example" {
				name                = "storageaccountname"
				resource_group_name = azurerm_resource_group.example.name
			  
				location                 = azurerm_resource_group.example.location
				account_tier             = "Standard"
				account_replication_type = "LRS"
				min_tls_version          = "TLS1_2"
			  
				network_rules {
				  default_action             = "Deny"
				  ip_rules                   = ["100.0.0.1"]
				  virtual_network_subnet_ids = [azurerm_subnet.example.id]
				}
			  
				tags = {
				  environment = "staging"
				}
			 
				   }`, `
				   			resource "azurerm_resource_group" "example" {
					name     = "example-resources"
					location = "West Europe"
				  }
				  
				  resource "azurerm_virtual_network" "example" {
					name                = "virtnetname"
					address_space       = ["10.0.0.0/16"]
					location            = azurerm_resource_group.example.location
					resource_group_name = azurerm_resource_group.example.name
				  }
				  
				  resource "azurerm_subnet" "example" {
					name                 = "subnetname"
					resource_group_name  = azurerm_resource_group.example.name
					virtual_network_name = azurerm_virtual_network.example.name
					address_prefixes     = ["10.0.2.0/24"]
					service_endpoints    = ["Microsoft.Sql", "Microsoft.Storage"]
				  }
				  
				  resource "azurerm_storage_account" "example" {
					name                = "storageaccountname"
					resource_group_name = azurerm_resource_group.example.name
				  
					location                 = azurerm_resource_group.example.location
					account_tier             = "Standard"
					account_replication_type = "LRS"
					min_tls_version          = "TLS1_2"
				  
					network_rules {
					  default_action             = "Deny"
					  ip_rules                   = ["100.0.0.1"]
					  virtual_network_subnet_ids = [azurerm_subnet.example.id]
					}
				  
					tags = {
					  environment = "staging"
					}
					blob_properties {
						container_delete_retention_policy {
							days = 7
						}
						}  
				  }`,
			},
			GoodExample: []string{`
				resource "azurerm_resource_group" "example" {
					name     = "example-resources"
					location = "West Europe"
				  }
				  
				  resource "azurerm_virtual_network" "example" {
					name                = "virtnetname"
					address_space       = ["10.0.0.0/16"]
					location            = azurerm_resource_group.example.location
					resource_group_name = azurerm_resource_group.example.name
				  }
				  
				  resource "azurerm_subnet" "example" {
					name                 = "subnetname"
					resource_group_name  = azurerm_resource_group.example.name
					virtual_network_name = azurerm_virtual_network.example.name
					address_prefixes     = ["10.0.2.0/24"]
					service_endpoints    = ["Microsoft.Sql", "Microsoft.Storage"]
				  }
				  
				  resource "azurerm_storage_account" "example" {
					name                = "storageaccountname"
					resource_group_name = azurerm_resource_group.example.name
				  
					location                 = azurerm_resource_group.example.location
					account_tier             = "Standard"
					account_replication_type = "LRS"
					min_tls_version          = "TLS1_2"
				  
					network_rules {
					  default_action             = "Deny"
					  ip_rules                   = ["100.0.0.1"]
					  virtual_network_subnet_ids = [azurerm_subnet.example.id]
					}
				  
					tags = {
					  environment = "staging"
					}
				   blob_properties {
					   delete_retention_policy {
						   days = 120
					   }
					   container_delete_retention_policy {
						days = 1
					  } 
				   } 
					   }
				`, `
				resource "azurerm_resource_group" "example" {
					name     = "example-resources"
					location = "West Europe"
				  }
				  
				  resource "azurerm_virtual_network" "example" {
					name                = "virtnetname"
					address_space       = ["10.0.0.0/16"]
					location            = azurerm_resource_group.example.location
					resource_group_name = azurerm_resource_group.example.name
				  }
				  
				  resource "azurerm_subnet" "example" {
					name                 = "subnetname"
					resource_group_name  = azurerm_resource_group.example.name
					virtual_network_name = azurerm_virtual_network.example.name
					address_prefixes     = ["10.0.2.0/24"]
					service_endpoints    = ["Microsoft.Sql", "Microsoft.Storage"]
				  }
				  
				  resource "azurerm_storage_account" "example" {
					name                = "storageaccountname"
					resource_group_name = azurerm_resource_group.example.name
				  
					location                 = azurerm_resource_group.example.location
					account_tier             = "Standard"
					account_replication_type = "LRS"
					min_tls_version          = "TLS1_2"
				  
					network_rules {
					  default_action             = "Deny"
					  ip_rules                   = ["100.0.0.1"]
					  virtual_network_subnet_ids = [azurerm_subnet.example.id]
					}
				  
					tags = {
					  environment = "staging"
					}
					blob_properties {
						delete_retention_policy {
							days = 1
						}
						container_delete_retention_policy{
							days = 1
						  } 
					}  
				  }
				`}, Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#delete_retention_policy",
				"https://docs.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-enable?tabs=azure-CLI"},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_storage_account"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {
			if resourceBlock.IsResourceType("azurerm_storage_account") {
				if resourceBlock.MissingChild("blob_properties") {
					set.AddResult().
						WithDescription("Resource '%s' does not have block blob_properties to set delete_retention_policy.", resourceBlock.FullName())
					return
				}
				resourceBlockChild := resourceBlock.GetBlock("blob_properties")
				if resourceBlockChild.MissingChild("delete_retention_policy") {
					set.AddResult().
						WithDescription("Block '%s' does not have delete_retention_policy block in resource '%s' ", resourceBlockChild.FullName(), resourceBlock.FullName())
					return
				}
				resourceBlockDeleteRetention := resourceBlockChild.GetBlock("delete_retention_policy")
				if resourceBlockDeleteRetention.MissingChild("days") {
					set.AddResult().
						WithDescription("Resource Block '%s' does not have  attribute days   in  resource '%s' ", resourceBlockDeleteRetention.FullName(), resourceBlock.FullName())
					return
				}
			}
		},
	})
}
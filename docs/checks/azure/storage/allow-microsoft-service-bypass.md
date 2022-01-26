---
title: Trusted Microsoft Services should have bypass access to Storage accounts
---

# Trusted Microsoft Services should have bypass access to Storage accounts

### Default Severity: <span class="severity high">high</span>

### Explanation

Some Microsoft services that interact with storage accounts operate from networks that can't be granted access through network rules. 

To help this type of service work as intended, allow the set of trusted Microsoft services to bypass the network rules

### Possible Impact
Trusted Microsoft Services won't be able to access storage account unless rules set to allow

### Suggested Resolution
Allow Trusted Microsoft Services to bypass


### Insecure Example

The following example will fail the azure-storage-allow-microsoft-service-bypass check.
```terraform

 resource "azurerm_storage_account" "bad_example" {
   name                = "storageaccountname"
   resource_group_name = azurerm_resource_group.example.name
 
   location                 = azurerm_resource_group.example.location
   account_tier             = "Standard"
   account_replication_type = "LRS"
 
   network_rules {
     default_action             = "Deny"
     ip_rules                   = ["100.0.0.1"]
     virtual_network_subnet_ids = [azurerm_subnet.example.id]
 	bypass                     = ["Metrics"]
   }
 
   tags = {
     environment = "staging"
   }
 }
 
 resource "azurerm_storage_account_network_rules" "test" {
   resource_group_name  = azurerm_resource_group.test.name
   storage_account_name = azurerm_storage_account.test.name
 
   default_action             = "Allow"
   ip_rules                   = ["127.0.0.1"]
   virtual_network_subnet_ids = [azurerm_subnet.test.id]
   bypass                     = ["Metrics"]
 }
 
```



### Secure Example

The following example will pass the azure-storage-allow-microsoft-service-bypass check.
```terraform

 resource "azurerm_storage_account" "good_example" {
   name                = "storageaccountname"
   resource_group_name = azurerm_resource_group.example.name
 
   location                 = azurerm_resource_group.example.location
   account_tier             = "Standard"
   account_replication_type = "LRS"
 
   network_rules {
     default_action             = "Deny"
     ip_rules                   = ["100.0.0.1"]
     virtual_network_subnet_ids = [azurerm_subnet.example.id]
     bypass                     = ["Metrics", "AzureServices"]
   }
 
   tags = {
     environment = "staging"
   }
 }
 
 resource "azurerm_storage_account_network_rules" "test" {
   resource_group_name  = azurerm_resource_group.test.name
   storage_account_name = azurerm_storage_account.test.name
 
   default_action             = "Allow"
   ip_rules                   = ["127.0.0.1"]
   virtual_network_subnet_ids = [azurerm_subnet.test.id]
   bypass                     = ["Metrics", "AzureServices"]
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#bypass](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#bypass){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#bypass](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#bypass){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security#trusted-microsoft-services](https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security#trusted-microsoft-services){:target="_blank" rel="nofollow noreferrer noopener"}




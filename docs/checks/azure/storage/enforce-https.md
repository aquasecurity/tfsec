---
title: Storage accounts should be configured to only accept transfers that are over secure connections
---

# Storage accounts should be configured to only accept transfers that are over secure connections

### Default Severity: <span class="severity high">high</span>

### Explanation

You can configure your storage account to accept requests from secure connections only by setting the Secure transfer required property for the storage account. 

When you require secure transfer, any requests originating from an insecure connection are rejected. 

Microsoft recommends that you always require secure transfer for all of your storage accounts.

### Possible Impact
Insecure transfer of data into secure accounts could be read if intercepted

### Suggested Resolution
Only allow secure connection for transferring data into storage accounts


### Insecure Example

The following example will fail the azure-storage-enforce-https check.
```terraform

 resource "azurerm_storage_account" "bad_example" {
   name                      = "storageaccountname"
   resource_group_name       = azurerm_resource_group.example.name
   location                  = azurerm_resource_group.example.location
   account_tier              = "Standard"
   account_replication_type  = "GRS"
   enable_https_traffic_only = false
 }
 
```



### Secure Example

The following example will pass the azure-storage-enforce-https check.
```terraform

 resource "azurerm_storage_account" "good_example" {
   name                      = "storageaccountname"
   resource_group_name       = azurerm_resource_group.example.name
   location                  = azurerm_resource_group.example.location
   account_tier              = "Standard"
   account_replication_type  = "GRS"
   enable_https_traffic_only = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#enable_https_traffic_only](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#enable_https_traffic_only){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer](https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer){:target="_blank" rel="nofollow noreferrer noopener"}




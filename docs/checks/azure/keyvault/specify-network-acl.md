---
title: Key vault should have the network acl block specified
---

# Key vault should have the network acl block specified

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Network ACLs allow you to reduce your exposure to risk by limiting what can access your key vault. 

The default action of the Network ACL should be set to deny for when IPs are not matched. Azure services can be allowed to bypass.

### Possible Impact
Without a network ACL the key vault is freely accessible

### Suggested Resolution
Set a network ACL for the key vault


### Insecure Example

The following example will fail the azure-keyvault-specify-network-acl check.
```terraform

 resource "azurerm_key_vault" "bad_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.bad_example.location
     enabled_for_disk_encryption = true
     soft_delete_retention_days  = 7
     purge_protection_enabled    = false
 }
 
```



### Secure Example

The following example will pass the azure-keyvault-specify-network-acl check.
```terraform

 resource "azurerm_key_vault" "good_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.good_example.location
     enabled_for_disk_encryption = true
     soft_delete_retention_days  = 7
     purge_protection_enabled    = false
 
     network_acls {
         bypass = "AzureServices"
         default_action = "Deny"
     }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#network_acls](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#network_acls){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/key-vault/general/network-security](https://docs.microsoft.com/en-us/azure/key-vault/general/network-security){:target="_blank" rel="nofollow noreferrer noopener"}




---
title: Key vault should have purge protection enabled
---

# Key vault should have purge protection enabled

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Purge protection is an optional Key Vault behavior and is not enabled by default.

Purge protection can only be enabled once soft-delete is enabled. It can be turned on via CLI or PowerShell.

### Possible Impact
Keys could be purged from the vault without protection

### Suggested Resolution
Enable purge protection for key vaults


### Insecure Example

The following example will fail the azure-keyvault-no-purge check.
```terraform

 resource "azurerm_key_vault" "bad_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.bad_example.location
     enabled_for_disk_encryption = true
     purge_protection_enabled    = false
 }
 
```



### Secure Example

The following example will pass the azure-keyvault-no-purge check.
```terraform

 resource "azurerm_key_vault" "good_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.good_example.location
     enabled_for_disk_encryption = true
     soft_delete_retention_days  = 7
     purge_protection_enabled    = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#purge_protection_enabled](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#purge_protection_enabled){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview#purge-protection](https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview#purge-protection){:target="_blank" rel="nofollow noreferrer noopener"}




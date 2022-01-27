---
title: Ensure that the expiration date is set on all keys
---

# Ensure that the expiration date is set on all keys

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Expiration Date is an optional Key Vault Key behavior and is not set by default.

Set when the resource will be become inactive.

### Possible Impact
Long life keys increase the attack surface when compromised

### Suggested Resolution
Set an expiration date on the vault key


### Insecure Example

The following example will fail the azure-keyvault-ensure-key-expiry check.
```terraform

 resource "azurerm_key_vault_key" "bad_example" {
   name         = "generated-certificate"
   key_vault_id = azurerm_key_vault.example.id
   key_type     = "RSA"
   key_size     = 2048
 
   key_opts = [
     "decrypt",
     "encrypt",
     "sign",
     "unwrapKey",
     "verify",
     "wrapKey",
   ]
 }
 
```



### Secure Example

The following example will pass the azure-keyvault-ensure-key-expiry check.
```terraform

 resource "azurerm_key_vault_key" "good_example" {
   name         = "generated-certificate"
   key_vault_id = azurerm_key_vault.example.id
   key_type     = "RSA"
   key_size     = 2048
   expiration_date = "1982-12-31T00:00:00Z"
 
   key_opts = [
     "decrypt",
     "encrypt",
     "sign",
     "unwrapKey",
     "verify",
     "wrapKey",
   ]
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_key#expiration_date](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_key#expiration_date){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/powershell/module/az.keyvault/update-azkeyvaultkey?view=azps-5.8.0#example-1--modify-a-key-to-enable-it--and-set-the-expiration-date-and-tags](https://docs.microsoft.com/en-us/powershell/module/az.keyvault/update-azkeyvaultkey?view=azps-5.8.0#example-1--modify-a-key-to-enable-it--and-set-the-expiration-date-and-tags){:target="_blank" rel="nofollow noreferrer noopener"}




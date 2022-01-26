---
title: Key Vault Secret should have an expiration date set
---

# Key Vault Secret should have an expiration date set

### Default Severity: <span class="severity low">low</span>

### Explanation

Expiration Date is an optional Key Vault Secret behavior and is not set by default.

Set when the resource will be become inactive.

### Possible Impact
Long life secrets increase the opportunity for compromise

### Suggested Resolution
Set an expiry for secrets


### Insecure Example

The following example will fail the azure-keyvault-ensure-secret-expiry check.
```terraform

 resource "azurerm_key_vault_secret" "bad_example" {
   name         = "secret-sauce"
   value        = "szechuan"
   key_vault_id = azurerm_key_vault.example.id
 }
 
```



### Secure Example

The following example will pass the azure-keyvault-ensure-secret-expiry check.
```terraform

 resource "azurerm_key_vault_secret" "good_example" {
   name            = "secret-sauce"
   value           = "szechuan"
   key_vault_id    = azurerm_key_vault.example.id
   expiration_date = "1982-12-31T00:00:00Z"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret#expiration_date](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret#expiration_date){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets](https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets){:target="_blank" rel="nofollow noreferrer noopener"}




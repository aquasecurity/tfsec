---
title: Key vault Secret should have a content type set
---

# Key vault Secret should have a content type set

### Default Severity: <span class="severity low">low</span>

### Explanation

Content Type is an optional Key Vault Secret behavior and is not enabled by default.

Clients may specify the content type of a secret to assist in interpreting the secret data when it's retrieved. The maximum length of this field is 255 characters. There are no pre-defined values. The suggested usage is as a hint for interpreting the secret data.

### Possible Impact
The secret's type is unclear without a content type

### Suggested Resolution
Provide content type for secrets to aid interpretation on retrieval


### Insecure Example

The following example will fail the azure-keyvault-content-type-for-secret check.
```terraform

 resource "azurerm_key_vault_secret" "bad_example" {
   name         = "secret-sauce"
   value        = "szechuan"
   key_vault_id = azurerm_key_vault.example.id
 }
 
```



### Secure Example

The following example will pass the azure-keyvault-content-type-for-secret check.
```terraform

 resource "azurerm_key_vault_secret" "good_example" {
   name         = "secret-sauce"
   value        = "szechuan"
   key_vault_id = azurerm_key_vault.example.id
   content_type = "password"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret#content_type](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret#content_type){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets](https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets){:target="_blank" rel="nofollow noreferrer noopener"}




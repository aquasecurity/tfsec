---
title: The minimum TLS version for Storage Accounts should be TLS1_2
---

# The minimum TLS version for Storage Accounts should be TLS1_2

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Azure Storage currently supports three versions of the TLS protocol: 1.0, 1.1, and 1.2. 

Azure Storage uses TLS 1.2 on public HTTPS endpoints, but TLS 1.0 and TLS 1.1 are still supported for backward compatibility.

This check will warn if the minimum TLS is not set to TLS1_2.

### Possible Impact
The TLS version being outdated and has known vulnerabilities

### Suggested Resolution
Use a more recent TLS/SSL policy for the load balancer


### Insecure Example

The following example will fail the azure-storage-use-secure-tls-policy check.
```terraform

 resource "azurerm_storage_account" "bad_example" {
   name                     = "storageaccountname"
   resource_group_name      = azurerm_resource_group.example.name
   location                 = azurerm_resource_group.example.location
 }
 
```



### Secure Example

The following example will pass the azure-storage-use-secure-tls-policy check.
```terraform

 resource "azurerm_storage_account" "good_example" {
   name                     = "storageaccountname"
   resource_group_name      = azurerm_resource_group.example.name
   location                 = azurerm_resource_group.example.location
   min_tls_version          = "TLS1_2"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#min_tls_version](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#min_tls_version){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version](https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version){:target="_blank" rel="nofollow noreferrer noopener"}




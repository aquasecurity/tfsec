---
title: Data Factory should have public access disabled, the default is enabled.
---

# Data Factory should have public access disabled, the default is enabled.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Data Factory has public access set to true by default.

Disabling public network access is applicable only to the self-hosted integration runtime, not to Azure Integration Runtime and SQL Server Integration Services (SSIS) Integration Runtime.

### Possible Impact
Data factory is publicly accessible

### Suggested Resolution
Set public access to disabled for Data Factory


### Insecure Example

The following example will fail the azure-datafactory-no-public-access check.
```terraform

 resource "azurerm_data_factory" "bad_example" {
   name                = "example"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
 }
 
```



### Secure Example

The following example will pass the azure-datafactory-no-public-access check.
```terraform

 resource "azurerm_data_factory" "good_example" {
   name                = "example"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   public_network_enabled = false
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/data_factory#public_network_enabled](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/data_factory#public_network_enabled){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/data-factory/data-movement-security-considerations#hybrid-scenarios](https://docs.microsoft.com/en-us/azure/data-factory/data-movement-security-considerations#hybrid-scenarios){:target="_blank" rel="nofollow noreferrer noopener"}




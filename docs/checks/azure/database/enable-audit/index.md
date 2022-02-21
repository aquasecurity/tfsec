---
title: Auditing should be enabled on Azure SQL Databases
---

# Auditing should be enabled on Azure SQL Databases

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Auditing helps you maintain regulatory compliance, understand database activity, and gain insight into discrepancies and anomalies that could indicate business concerns or suspected security violations.

### Possible Impact
Auditing provides valuable information about access and usage

### Suggested Resolution
Enable auditing on Azure SQL databases


### Insecure Example

The following example will fail the azure-database-enable-audit check.
```terraform

 resource "azurerm_sql_server" "bad_example" {
   name                         = "mssqlserver"
   resource_group_name          = azurerm_resource_group.example.name
   location                     = azurerm_resource_group.example.location
   version                      = "12.0"
   administrator_login          = "mradministrator"
   administrator_login_password = "tfsecRocks"
 }
 
```



### Secure Example

The following example will pass the azure-database-enable-audit check.
```terraform

 resource "azurerm_sql_server" "good_example" {
   name                         = "mssqlserver"
   resource_group_name          = azurerm_resource_group.example.name
   location                     = azurerm_resource_group.example.location
   version                      = "12.0"
   administrator_login          = "mradministrator"
   administrator_login_password = "tfsecRocks"
 
   extended_auditing_policy {
     storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
     storage_account_access_key              = azurerm_storage_account.example.primary_access_key
     storage_account_access_key_is_secondary = true
     retention_in_days                       = 6
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server#extended_auditing_policy](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server#extended_auditing_policy){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview](https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview){:target="_blank" rel="nofollow noreferrer noopener"}




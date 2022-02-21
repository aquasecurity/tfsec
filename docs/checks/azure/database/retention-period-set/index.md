---
title: Database auditing rentention period should be longer than 90 days
---

# Database auditing rentention period should be longer than 90 days

### Default Severity: <span class="severity medium">medium</span>

### Explanation

When Auditing is configured for a SQL database, if the retention period is not set, the retention will be unlimited.

If the retention period is to be explicitly set, it should be set for no less than 90 days.

### Possible Impact
Short logging retention could result in missing valuable historical information

### Suggested Resolution
Set retention periods of database auditing to greater than 90 days


### Insecure Example

The following example will fail the azure-database-retention-period-set check.
```terraform

 resource "azurerm_mssql_database_extended_auditing_policy" "bad_example" {
   database_id                             = azurerm_mssql_database.example.id
   storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
   storage_account_access_key              = azurerm_storage_account.example.primary_access_key
   storage_account_access_key_is_secondary = false
   retention_in_days                       = 6
 }
 
```



### Secure Example

The following example will pass the azure-database-retention-period-set check.
```terraform

 resource "azurerm_mssql_database_extended_auditing_policy" "good_example" {
   database_id                             = azurerm_mssql_database.example.id
   storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
   storage_account_access_key              = azurerm_storage_account.example.primary_access_key
   storage_account_access_key_is_secondary = false
 }
 
 resource "azurerm_mssql_database_extended_auditing_policy" "good_example" {
   database_id                             = azurerm_mssql_database.example.id
   storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
   storage_account_access_key              = azurerm_storage_account.example.primary_access_key
   storage_account_access_key_is_secondary = false
   retention_in_days                       = 90
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_database_extended_auditing_policy](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_database_extended_auditing_policy){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server#retention_in_days](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server#retention_in_days){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview](https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview){:target="_blank" rel="nofollow noreferrer noopener"}




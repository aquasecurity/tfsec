---
title: No threat detections are set
---

# No threat detections are set

### Default Severity: <span class="severity medium">medium</span>

### Explanation

SQL Server can alert for security issues including SQL Injection, vulnerabilities, access anomalies and data exfiltration. Ensure none of these are disabled to benefit from the best protection

### Possible Impact
Disabling threat alerts means you are not getting the full benefit of server security protection

### Suggested Resolution
Use all provided threat alerts


### Insecure Example

The following example will fail the azure-database-all-threat-alerts-enabled check.
```terraform

 resource "azurerm_mssql_server_security_alert_policy" "bad_example" {
   resource_group_name        = azurerm_resource_group.example.name
   server_name                = azurerm_sql_server.example.name
   state                      = "Enabled"
   storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
   storage_account_access_key = azurerm_storage_account.example.primary_access_key
   disabled_alerts = [
     "Sql_Injection",
     "Data_Exfiltration"
   ]
   retention_days = 20
 }
 
```



### Secure Example

The following example will pass the azure-database-all-threat-alerts-enabled check.
```terraform

 resource "azurerm_mssql_server_security_alert_policy" "good_example" {
   resource_group_name        = azurerm_resource_group.example.name
   server_name                = azurerm_sql_server.example.name
   state                      = "Enabled"
   storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
   storage_account_access_key = azurerm_storage_account.example.primary_access_key
   disabled_alerts = []
   retention_days = 20
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#disabled_alerts](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#disabled_alerts){:target="_blank" rel="nofollow noreferrer noopener"}




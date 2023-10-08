---
title: At least one email address is set for threat alerts
---

# At least one email address is set for threat alerts

### Default Severity: <span class="severity medium">medium</span>

### Explanation

SQL Server sends alerts for threat detection via email, if there are no email addresses set then mitigation will be delayed.

### Possible Impact
Nobody will be promptly alerted in the case of a threat being detected

### Suggested Resolution
Provide at least one email address for threat alerts


### Insecure Example

The following example will fail the azure-database-threat-alert-email-set check.
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
   email_addresses = []
 }
 
```



### Secure Example

The following example will pass the azure-database-threat-alert-email-set check.
```terraform

 resource "azurerm_mssql_server_security_alert_policy" "good_example" {
   resource_group_name        = azurerm_resource_group.example.name
   server_name                = azurerm_sql_server.example.name
   state                      = "Enabled"
   storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
   storage_account_access_key = azurerm_storage_account.example.primary_access_key
   disabled_alerts = [
     "Sql_Injection",
     "Data_Exfiltration"
   ]
   email_addresses = ["db-security@acme.org"]
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#email_addresses](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#email_addresses){:target="_blank" rel="nofollow noreferrer noopener"}




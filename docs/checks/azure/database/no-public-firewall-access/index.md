---
title: Ensure database firewalls do not permit public access
---

# Ensure database firewalls do not permit public access

### Default Severity: <span class="severity high">high</span>

### Explanation

Azure services can be allowed access through the firewall using a start and end IP address of 0.0.0.0. No other end ip address should be combined with a start of 0.0.0.0

### Possible Impact
Publicly accessible databases could lead to compromised data

### Suggested Resolution
Don't use wide ip ranges for the sql firewall


### Insecure Example

The following example will fail the azure-database-no-public-firewall-access check.
```terraform

 resource "azurerm_sql_firewall_rule" "bad_example" {
   name                = "bad_rule"
   resource_group_name = azurerm_resource_group.example.name
   server_name         = azurerm_sql_server.example.name
   start_ip_address    = "0.0.0.0"
   end_ip_address      = "255.255.255.255"
 }
 
 resource "azurerm_postgresql_firewall_rule" "bad_example" {
   name                = "bad_example"
   resource_group_name = azurerm_resource_group.example.name
   server_name         = azurerm_postgresql_server.example.name
   start_ip_address    = "0.0.0.0"
   end_ip_address      = "255.255.255.255"
 }
 
```



### Secure Example

The following example will pass the azure-database-no-public-firewall-access check.
```terraform

 resource "azurerm_sql_firewall_rule" "good_example" {
   name                = "good_rule"
   resource_group_name = azurerm_resource_group.example.name
   server_name         = azurerm_sql_server.example.name
   start_ip_address    = "0.0.0.0"
   end_ip_address      = "0.0.0.0"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_firewall_rule#end_ip_address](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_firewall_rule#end_ip_address){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/rest/api/sql/2021-02-01-preview/firewall-rules/create-or-update](https://docs.microsoft.com/en-us/rest/api/sql/2021-02-01-preview/firewall-rules/create-or-update){:target="_blank" rel="nofollow noreferrer noopener"}




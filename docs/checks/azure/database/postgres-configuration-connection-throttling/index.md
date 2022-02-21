---
title: Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server
---

# Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Postgresql can generate logs for connection throttling to improve visibility for audit and configuration issue resolution.

### Possible Impact
No log information to help diagnosing connection contention issues

### Suggested Resolution
Enable connection throttling logging


### Insecure Example

The following example will fail the azure-database-postgres-configuration-connection-throttling check.
```terraform

 resource "azurerm_resource_group" "example" {
   name     = "example-resources"
   location = "West Europe"
 }
 
 resource "azurerm_postgresql_server" "example" {
   name                = "example-psqlserver"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
 
   administrator_login          = "psqladminun"
   administrator_login_password = "H@Sh1CoR3!"
 
   sku_name   = "GP_Gen5_4"
   version    = "9.6"
   storage_mb = 640000
 }
 
```



### Secure Example

The following example will pass the azure-database-postgres-configuration-connection-throttling check.
```terraform

 resource "azurerm_resource_group" "example" {
   name     = "example-resources"
   location = "West Europe"
 }
 
 resource "azurerm_postgresql_server" "example" {
   name                = "example-psqlserver"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
 
   administrator_login          = "psqladminun"
   administrator_login_password = "H@Sh1CoR3!"
 
   sku_name   = "GP_Gen5_4"
   version    = "9.6"
   storage_mb = 640000
 }
 
 resource "azurerm_postgresql_configuration" "example" {
 	name                = "connection_throttling"
 	resource_group_name = azurerm_resource_group.example.name
 	server_name         = azurerm_postgresql_server.example.name
 	value               = "on"
   }
   
   
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging](https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging){:target="_blank" rel="nofollow noreferrer noopener"}




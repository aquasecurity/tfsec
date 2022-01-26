---
title: Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server
---

# Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Postgresql can generate logs for successful connections to improve visibility for audit and configuration issue resolution.

### Possible Impact
No visibility of successful connections

### Suggested Resolution
Enable connection logging


### Insecure Example

The following example will fail the azure-database-postgres-configuration-log-connections check.
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

The following example will pass the azure-database-postgres-configuration-log-connections check.
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
 	name                = "log_connections"
 	resource_group_name = azurerm_resource_group.example.name
 	server_name         = azurerm_postgresql_server.example.name
 	value               = "on"
   }
   
   
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging](https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging](https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging){:target="_blank" rel="nofollow noreferrer noopener"}




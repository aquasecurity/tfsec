---
title: Databases should have the minimum TLS set for connections
---

# Databases should have the minimum TLS set for connections

### Default Severity: <span class="severity medium">medium</span>

### Explanation

You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.

### Possible Impact
Outdated TLS policies increase exposure to known issues

### Suggested Resolution
Use the most modern TLS policies available


### Insecure Example

The following example will fail the azure-database-secure-tls-policy check.
```terraform

 resource "azurerm_mssql_server" "bad_example" {
   name                         = "mssqlserver"
   resource_group_name          = azurerm_resource_group.example.name
   location                     = azurerm_resource_group.example.location
   version                      = "12.0"
   administrator_login          = "missadministrator"
   administrator_login_password = "thisIsKat11"
   minimum_tls_version          = "1.1"
 }
 
 resource "azurerm_postgresql_server" "bad_example" {
 	name                = "bad_example"
   
 	public_network_access_enabled    = true
 	ssl_enforcement_enabled          = false
 	ssl_minimal_tls_version_enforced = "TLS1_1"
   }
 
```



### Secure Example

The following example will pass the azure-database-secure-tls-policy check.
```terraform

 resource "azurerm_mssql_server" "good_example" {
   name                         = "mssqlserver"
   resource_group_name          = azurerm_resource_group.example.name
   location                     = azurerm_resource_group.example.location
   version                      = "12.0"
   administrator_login          = "missadministrator"
   administrator_login_password = "thisIsKat11"
   minimum_tls_version          = "1.2"
 }
 
 resource "azurerm_postgresql_server" "good_example" {
   name                = "bad_example"
 
   public_network_access_enabled    = true
   ssl_enforcement_enabled          = false
   ssl_minimal_tls_version_enforced = "TLS1_2"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server#minimum_tls_version](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server#minimum_tls_version){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#ssl_minimal_tls_version_enforced](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#ssl_minimal_tls_version_enforced){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#ssl_minimal_tls_version_enforced](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#ssl_minimal_tls_version_enforced){:target="_blank" rel="nofollow noreferrer noopener"}




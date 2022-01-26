---
title: SSL should be enforced on database connections where applicable
---

# SSL should be enforced on database connections where applicable

### Default Severity: <span class="severity medium">medium</span>

### Explanation

SSL connections should be enforced were available to ensure secure transfer and reduce the risk of compromising data in flight.

### Possible Impact
Insecure connections could lead to data loss and other vulnerabilities

### Suggested Resolution
Enable SSL enforcement


### Insecure Example

The following example will fail the azure-database-enable-ssl-enforcement check.
```terraform

 resource "azurerm_postgresql_server" "bad_example" {
   name                = "bad_example"
 
   public_network_access_enabled    = false
   ssl_enforcement_enabled          = false
   ssl_minimal_tls_version_enforced = "TLS1_2"
 }
 
```



### Secure Example

The following example will pass the azure-database-enable-ssl-enforcement check.
```terraform

 resource "azurerm_postgresql_server" "good_example" {
   name                = "good_example"
 
   public_network_access_enabled    = false
   ssl_enforcement_enabled          = true
   ssl_minimal_tls_version_enforced = "TLS1_2"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#ssl_enforcement_enabled](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#ssl_enforcement_enabled){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#ssl_enforcement_enabled](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#ssl_enforcement_enabled){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server#ssl_enforcement_enabled](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server#ssl_enforcement_enabled){:target="_blank" rel="nofollow noreferrer noopener"}




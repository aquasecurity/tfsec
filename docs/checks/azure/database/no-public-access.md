---
title: no-public-access
---

### Explanation

Database resources should not publicly available. You should limit all access to the minimum that is required for your application to function.

### Possible Impact
Publicly accessible database could lead to compromised data

### Suggested Resolution
Disable public access to database when not required


### Insecure Example

The following example will fail the azure-database-no-public-access check.

```terraform

resource "azurerm_postgresql_server" "bad_example" {
  name                = "bad_example"

  public_network_access_enabled    = true
  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_2"
}

```



### Secure Example

The following example will pass the azure-database-no-public-access check.

```terraform

resource "azurerm_postgresql_server" "good_example" {
  name                = "bad_example"

  public_network_access_enabled    = false
  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_2"
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#public_network_access_enabled](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#public_network_access_enabled){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#public_network_access_enabled](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#public_network_access_enabled){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server#public_network_access_enabled](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server#public_network_access_enabled){:target="_blank" rel="nofollow noreferrer noopener"}



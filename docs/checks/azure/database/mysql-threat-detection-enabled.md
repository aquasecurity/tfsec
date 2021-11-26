---
title: mysql-threat-detection-enabled
---

### Explanation

My SQL server does not enable Threat Detection policy

### Possible Impact
Threat detection helps prevent compromise by alerting on threat detections

### Suggested Resolution
Enable threat detection on Mysql database


### Insecure Example

The following example will fail the azure-database-mysql-threat-detection-enabled check.

```terraform

resource "azurerm_mysql_server" "bad_example" {
  name                = "bad_example"

  public_network_access_enabled    = true
  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_2"

  threat_detection_policy {
    enabled = false
  }
}

```



### Secure Example

The following example will pass the azure-database-mysql-threat-detection-enabled check.

```terraform

resource "azurerm_mysql_server" "good_example" {
  name                = "good_example"

  public_network_access_enabled    = false
  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_2"

  threat_detection_policy {
    enabled = true
  }
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/mysql_server#threat_detection_policy](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/mysql_server#threat_detection_policy){:target="_blank" rel="nofollow noreferrer noopener"}



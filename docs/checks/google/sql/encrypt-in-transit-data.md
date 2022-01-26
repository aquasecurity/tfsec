---
title: SSL connections to a SQL database instance should be enforced.
---

# SSL connections to a SQL database instance should be enforced.

### Default Severity: <span class="severity high">high</span>

### Explanation

In-transit data should be encrypted so that if traffic is intercepted data will not be exposed in plaintext to attackers.

### Possible Impact
Intercepted data can be read in transit

### Suggested Resolution
Enforce SSL for all connections


### Insecure Example

The following example will fail the google-sql-encrypt-in-transit-data check.
```terraform

 resource "google_sql_database_instance" "postgres" {
 	name             = "postgres-instance-a"
 	database_version = "POSTGRES_11"
 	
 	settings {
 		tier = "db-f1-micro"
 	
 		ip_configuration {
 			ipv4_enabled = false
 			authorized_networks {
 				value           = "108.12.12.0/24"
 				name            = "internal"
 			}
 			require_ssl = false
 		}
 	}
 }
 			
```



### Secure Example

The following example will pass the google-sql-encrypt-in-transit-data check.
```terraform

 resource "google_sql_database_instance" "postgres" {
 	name             = "postgres-instance-a"
 	database_version = "POSTGRES_11"
 	
 	settings {
 		tier = "db-f1-micro"
 	
 		ip_configuration {
 			ipv4_enabled = false
 			authorized_networks {
 				value           = "108.12.12.0/24"
 				name            = "internal"
 			}
 			require_ssl = true
 		}
 	}
 }
 			
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/sql/docs/mysql/configure-ssl-instance](https://cloud.google.com/sql/docs/mysql/configure-ssl-instance){:target="_blank" rel="nofollow noreferrer noopener"}




---
title: Cross-database ownership chaining should be disabled
---

# Cross-database ownership chaining should be disabled

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Cross-database ownership chaining, also known as cross-database chaining, is a security feature of SQL Server that allows users of databases access to other databases besides the one they are currently using.

### Possible Impact
Unintended access to sensitive data

### Suggested Resolution
Disable cross database ownership chaining


### Insecure Example

The following example will fail the google-sql-no-cross-db-ownership-chaining check.
```terraform

 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "SQLSERVER_2017_STANDARD"
 	region           = "us-central1"
 }
 			
```



### Secure Example

The following example will pass the google-sql-no-cross-db-ownership-chaining check.
```terraform

 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "SQLSERVER_2017_STANDARD"
 	region           = "us-central1"
 	settings {
 	    database_flags {
 		    name  = "cross db ownership chaining"
 		    value = "off"
 		}
 	}
 }
 			
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/cross-db-ownership-chaining-server-configuration-option?view=sql-server-ver15](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/cross-db-ownership-chaining-server-configuration-option?view=sql-server-ver15){:target="_blank" rel="nofollow noreferrer noopener"}




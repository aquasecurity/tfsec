---
title: Contained database authentication should be disabled
---

# Contained database authentication should be disabled

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Users with ALTER permissions on users can grant access to a contained database without the knowledge of an administrator

### Possible Impact
Access can be granted without knowledge of the database administrator

### Suggested Resolution
Disable contained database authentication


### Insecure Example

The following example will fail the google-sql-no-contained-db-auth check.
```terraform

 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "SQLSERVER_2017_STANDARD"
 	region           = "us-central1"
 }
 			
```



### Secure Example

The following example will pass the google-sql-no-contained-db-auth check.
```terraform

 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "SQLSERVER_2017_STANDARD"
 	region           = "us-central1"
 	settings {
 	    database_flags {
 		    name  = "contained database authentication"
 		    value = "off"
 		}
 	}
 }
 			
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/contained-database-authentication-server-configuration-option?view=sql-server-ver15](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/contained-database-authentication-server-configuration-option?view=sql-server-ver15){:target="_blank" rel="nofollow noreferrer noopener"}




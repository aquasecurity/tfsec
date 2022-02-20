---
title: Disable local_infile setting in MySQL
---

# Disable local_infile setting in MySQL

### Default Severity: <span class="severity high">high</span>

### Explanation

Arbitrary files can be read from the system using LOAD_DATA unless this setting is disabled.

### Possible Impact
Arbitrary files read by attackers when combined with a SQL injection vulnerability.

### Suggested Resolution
Disable the local infile setting


### Insecure Example

The following example will fail the google-sql-mysql-no-local-infile check.
```terraform

 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "MYSQL_5_6"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "local_infile"
 			value = "on"
 		}
 	}
 }
 			
```



### Secure Example

The following example will pass the google-sql-mysql-no-local-infile check.
```terraform

 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "MYSQL_5_6"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "local_infile"
 			value = "off"
 		}
 	}
 }
 			
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html](https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html](https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html){:target="_blank" rel="nofollow noreferrer noopener"}




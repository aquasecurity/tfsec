---
title: Ensure that Postgres errors are logged
---

# Ensure that Postgres errors are logged

### Default Severity: <span class="severity low">low</span>

### Explanation

Setting the minimum log severity too high will cause errors not to be logged

### Possible Impact
Loss of error logging

### Suggested Resolution
Set the minimum log severity to at least ERROR


### Insecure Example

The following example will fail the google-sql-pg-log-errors check.
```terraform

 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_min_messages"
 			value = "PANIC"
 		}
 	}
 }
 			
```



### Secure Example

The following example will pass the google-sql-pg-log-errors check.
```terraform

 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_min_messages"
 			value = "WARNING"
 		}
 	}
 }
 			
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://postgresqlco.nf/doc/en/param/log_min_messages/](https://postgresqlco.nf/doc/en/param/log_min_messages/){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-MESSAGES](https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-MESSAGES){:target="_blank" rel="nofollow noreferrer noopener"}




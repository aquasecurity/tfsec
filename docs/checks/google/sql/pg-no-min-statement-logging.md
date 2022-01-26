---
title: Ensure that logging of long statements is disabled.
---

# Ensure that logging of long statements is disabled.

### Default Severity: <span class="severity low">low</span>

### Explanation

Logging of statements which could contain sensitive data is not advised, therefore this setting should preclude all statements from being logged.

### Possible Impact
Sensitive data could be exposed in the database logs.

### Suggested Resolution
Disable minimum duration statement logging completely


### Insecure Example

The following example will fail the google-sql-pg-no-min-statement-logging check.
```terraform

 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_min_duration_statement"
 			value = "99"
 		}
 	}
 }
 			
```



### Secure Example

The following example will pass the google-sql-pg-no-min-statement-logging check.
```terraform

 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_min_duration_statement"
 			value = "-1"
 		}
 	}
 }
 			
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-DURATION-STATEMENT](https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-DURATION-STATEMENT){:target="_blank" rel="nofollow noreferrer noopener"}




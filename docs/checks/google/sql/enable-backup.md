---
title: Enable automated backups to recover from data-loss
---

# Enable automated backups to recover from data-loss

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Automated backups are not enabled by default. Backups are an easy way to restore data in a corruption or data-loss scenario.

### Possible Impact
No recovery of lost or corrupted data

### Suggested Resolution
Enable automated backups


### Insecure Example

The following example will fail the google-sql-enable-backup check.
```terraform

 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		backup_configuration {
 			enabled = false
 		}
 	}
 }
 			
```



### Secure Example

The following example will pass the google-sql-enable-backup check.
```terraform

 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		backup_configuration {
 			enabled = true
 		}
 	}
 }
 			
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance#settings.backup_configuration.enabled=true](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance#settings.backup_configuration.enabled=true){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/sql/docs/mysql/backup-recovery/backups](https://cloud.google.com/sql/docs/mysql/backup-recovery/backups){:target="_blank" rel="nofollow noreferrer noopener"}




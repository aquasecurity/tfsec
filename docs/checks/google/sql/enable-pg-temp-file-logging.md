---
title: Temporary file logging should be enabled for all temporary files.
---

# Temporary file logging should be enabled for all temporary files.

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Temporary files are not logged by default. To log all temporary files, a value of `0` should set in the `log_temp_files` flag - as all files greater in size than the number of bytes set in this flag will be logged.

### Possible Impact
Use of temporary files will not be logged

### Suggested Resolution
Enable temporary file logging for all files


### Insecure Example

The following example will fail the google-sql-enable-pg-temp-file-logging check.
```terraform

 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 }
 			
```



### Secure Example

The following example will pass the google-sql-enable-pg-temp-file-logging check.
```terraform

 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 	    database_flags {
 		    name  = "log_temp_files"
 		    value = "0"
 		}
 	}
 }
 			
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://postgresqlco.nf/doc/en/param/log_temp_files/](https://postgresqlco.nf/doc/en/param/log_temp_files/){:target="_blank" rel="nofollow noreferrer noopener"}




---
title: RDB instance should have backup retention longer than 1 day
---

# RDB instance should have backup retention longer than 1 day

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Backup retention periods should be set to a period that is a balance on cost and limiting risk.

### Possible Impact
Potential loss of data and short opportunity for recovery

### Suggested Resolution
Explicitly set the retention period to greater than the default


### Insecure Example

The following example will fail the nifcloud-rdb-specify-backup-retention check.
```terraform

 resource "nifcloud_db_instance" "bad_example" {
 	allocated_storage    = 100
 	engine               = "mysql"
 	engine_version       = "5.7"
 	instance_class       = "db.large8"
 	name                 = "mydb"
 	username             = "foo"
 	password             = "foobarbaz"
 	parameter_group_name = "default.mysql5.7"
 	skip_final_snapshot  = true
 }

```



### Secure Example

The following example will pass the nifcloud-rdb-specify-backup-retention check.
```terraform
 
   resource "nifcloud_db_instance" "good_example" {
 	allocated_storage       = 100
 	engine                  = "mysql"
 	engine_version          = "5.7"
 	instance_class          = "db.large8"
 	name                    = "mydb"
 	username                = "foo"
 	password                = "foobarbaz"
 	parameter_group_name    = "default.mysql5.7"
 	backup_retention_period = 5
 	skip_final_snapshot     = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#backup_retention_period](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#backup_retention_period){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://pfs.nifcloud.com/spec/rdb/snapshot_backup.htm](https://pfs.nifcloud.com/spec/rdb/snapshot_backup.htm){:target="_blank" rel="nofollow noreferrer noopener"}




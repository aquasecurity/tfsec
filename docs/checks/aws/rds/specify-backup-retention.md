---
title: RDS Cluster and RDS instance should have backup retention longer than default 1 day
---

# RDS Cluster and RDS instance should have backup retention longer than default 1 day

### Default Severity: <span class="severity medium">medium</span>

### Explanation

RDS backup retention for clusters defaults to 1 day, this may not be enough to identify and respond to an issue. Backup retention periods should be set to a period that is a balance on cost and limiting risk.

### Possible Impact
Potential loss of data and short opportunity for recovery

### Suggested Resolution
Explicitly set the retention period to greater than the default


### Insecure Example

The following example will fail the aws-rds-specify-backup-retention check.
```terraform

 resource "aws_db_instance" "bad_example" {
 	allocated_storage    = 10
 	engine               = "mysql"
 	engine_version       = "5.7"
 	instance_class       = "db.t3.micro"
 	name                 = "mydb"
 	username             = "foo"
 	password             = "foobarbaz"
 	parameter_group_name = "default.mysql5.7"
 	skip_final_snapshot  = true
 }

```



### Secure Example

The following example will pass the aws-rds-specify-backup-retention check.
```terraform

 resource "aws_rds_cluster" "good_example" {
 	cluster_identifier      = "aurora-cluster-demo"
 	engine                  = "aurora-mysql"
 	engine_version          = "5.7.mysql_aurora.2.03.2"
 	availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
 	database_name           = "mydb"
 	master_username         = "foo"
 	master_password         = "bar"
 	backup_retention_period = 5
 	preferred_backup_window = "07:00-09:00"
   }
 

```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster#backup_retention_period](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster#backup_retention_period){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#backup_retention_period](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#backup_retention_period){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html#USER_WorkingWithAutomatedBackups.BackupRetention](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html#USER_WorkingWithAutomatedBackups.BackupRetention){:target="_blank" rel="nofollow noreferrer noopener"}




---
title: Neptune storage must be encrypted at rest
---

# Neptune storage must be encrypted at rest

### Default Severity: <span class="severity high">high</span>

### Explanation

Encryption of Neptune storage ensures that if their is compromise of the disks, the data is still protected.

### Possible Impact
Unencrypted sensitive data is vulnerable to compromise.

### Suggested Resolution
Enable encryption of Neptune storage


### Insecure Example

The following example will fail the aws-neptune-enable-storage-encryption check.
```terraform

 resource "aws_neptune_cluster" "bad_example" {
   cluster_identifier                  = "neptune-cluster-demo"
   engine                              = "neptune"
   backup_retention_period             = 5
   preferred_backup_window             = "07:00-09:00"
   skip_final_snapshot                 = true
   iam_database_authentication_enabled = true
   apply_immediately                   = true
   storage_encrypted                   = false
 }
 
```



### Secure Example

The following example will pass the aws-neptune-enable-storage-encryption check.
```terraform

 resource "aws_neptune_cluster" "good_example" {
   cluster_identifier                  = "neptune-cluster-demo"
   engine                              = "neptune"
   backup_retention_period             = 5
   preferred_backup_window             = "07:00-09:00"
   skip_final_snapshot                 = true
   iam_database_authentication_enabled = true
   apply_immediately                   = true
   storage_encrypted                   = true
   kms_key_arn                         = aws_kms_key.example.arn
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/neptune_cluster#storage_encrypted](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/neptune_cluster#storage_encrypted){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html](https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html){:target="_blank" rel="nofollow noreferrer noopener"}




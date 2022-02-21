---
title: DocumentDB storage must be encrypted
---

# DocumentDB storage must be encrypted

### Default Severity: <span class="severity high">high</span>

### Explanation

Encryption of the underlying storage used by DocumentDB ensures that if their is compromise of the disks, the data is still protected.

### Possible Impact
Unencrypted sensitive data is vulnerable to compromise.

### Suggested Resolution
Enable storage encryption


### Insecure Example

The following example will fail the aws-documentdb-enable-storage-encryption check.
```terraform

 resource "aws_docdb_cluster" "bad_example" {
   cluster_identifier      = "my-docdb-cluster"
   engine                  = "docdb"
   master_username         = "foo"
   master_password         = "mustbeeightchars"
   backup_retention_period = 5
   preferred_backup_window = "07:00-09:00"
   skip_final_snapshot     = true
   storage_encrypted = false
 }
 
```



### Secure Example

The following example will pass the aws-documentdb-enable-storage-encryption check.
```terraform

 resource "aws_docdb_cluster" "good_example" {
   cluster_identifier      = "my-docdb-cluster"
   engine                  = "docdb"
   master_username         = "foo"
   master_password         = "mustbeeightchars"
   backup_retention_period = 5
   preferred_backup_window = "07:00-09:00"
   skip_final_snapshot     = true
   storage_encrypted = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#storage_encrypted](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#storage_encrypted){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html](https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html){:target="_blank" rel="nofollow noreferrer noopener"}




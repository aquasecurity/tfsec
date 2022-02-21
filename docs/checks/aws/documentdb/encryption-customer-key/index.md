---
title: DocumentDB encryption should use Customer Managed Keys
---

# DocumentDB encryption should use Customer Managed Keys

### Default Severity: <span class="severity low">low</span>

### Explanation

Encryption using AWS keys provides protection for your DocumentDB underlying storage. To increase control of the encryption and manage factors like rotation use customer managed keys.

### Possible Impact
Using AWS managed keys does not allow for fine grained control

### Suggested Resolution
Enable encryption using customer managed keys


### Insecure Example

The following example will fail the aws-documentdb-encryption-customer-key check.
```terraform

 resource "aws_docdb_cluster" "docdb" {
   cluster_identifier      = "my-docdb-cluster"
   engine                  = "docdb"
   master_username         = "foo"
   master_password         = "mustbeeightchars"
   backup_retention_period = 5
   preferred_backup_window = "07:00-09:00"
   skip_final_snapshot     = true
 }
 
```



### Secure Example

The following example will pass the aws-documentdb-encryption-customer-key check.
```terraform

 resource "aws_kms_key" "docdb_encryption" {
 	enable_key_rotation = true
 }
 			
 resource "aws_docdb_cluster" "docdb" {
   cluster_identifier      = "my-docdb-cluster"
   engine                  = "docdb"
   master_username         = "foo"
   master_password         = "mustbeeightchars"
   backup_retention_period = 5
   preferred_backup_window = "07:00-09:00"
   skip_final_snapshot     = true
   kms_key_id 			  = aws_kms_key.docdb_encryption.arn
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#kms_key_id](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#kms_key_id){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.public-key.html](https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.public-key.html){:target="_blank" rel="nofollow noreferrer noopener"}




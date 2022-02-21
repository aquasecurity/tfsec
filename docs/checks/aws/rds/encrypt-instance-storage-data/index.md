---
title: RDS encryption has not been enabled at a DB Instance level.
---

# RDS encryption has not been enabled at a DB Instance level.

### Default Severity: <span class="severity high">high</span>

### Explanation

Encryption should be enabled for an RDS Database instances. 

When enabling encryption by setting the kms_key_id.

### Possible Impact
Data can be read from RDS instances if compromised

### Suggested Resolution
Enable encryption for RDS instances


### Insecure Example

The following example will fail the aws-rds-encrypt-instance-storage-data check.
```terraform

 resource "aws_db_instance" "bad_example" {
 	
 }
 
```



### Secure Example

The following example will pass the aws-rds-encrypt-instance-storage-data check.
```terraform

 resource "aws_db_instance" "good_example" {
 	storage_encrypted  = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html){:target="_blank" rel="nofollow noreferrer noopener"}




---
title: There is no encryption specified or encryption is disabled on the RDS Cluster.
---

# There is no encryption specified or encryption is disabled on the RDS Cluster.

### Default Severity: <span class="severity high">high</span>

### Explanation

Encryption should be enabled for an RDS Aurora cluster. 

When enabling encryption by setting the kms_key_id, the storage_encrypted must also be set to true.

### Possible Impact
Data can be read from the RDS cluster if it is compromised

### Suggested Resolution
Enable encryption for RDS clusters


### Insecure Example

The following example will fail the aws-rds-encrypt-cluster-storage-data check.
```terraform

 resource "aws_rds_cluster" "bad_example" {
   name       = "bar"
   kms_key_id = ""
 }
```



### Secure Example

The following example will pass the aws-rds-encrypt-cluster-storage-data check.
```terraform

 resource "aws_rds_cluster" "good_example" {
   name              = "bar"
   kms_key_id  = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
   storage_encrypted = true
 }
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html){:target="_blank" rel="nofollow noreferrer noopener"}




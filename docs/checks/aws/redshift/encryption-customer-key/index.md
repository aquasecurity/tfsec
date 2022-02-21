---
title: Redshift clusters should use at rest encryption
---

# Redshift clusters should use at rest encryption

### Default Severity: <span class="severity high">high</span>

### Explanation

Redshift clusters that contain sensitive data or are subject to regulation should be encrypted at rest to prevent data leakage should the infrastructure be compromised.

### Possible Impact
Data may be leaked if infrastructure is compromised

### Suggested Resolution
Enable encryption using CMK


### Insecure Example

The following example will fail the aws-redshift-encryption-customer-key check.
```terraform

 resource "aws_redshift_cluster" "bad_example" {
   cluster_identifier = "tf-redshift-cluster"
   database_name      = "mydb"
   master_username    = "foo"
   master_password    = "Mustbe8characters"
   node_type          = "dc1.large"
   cluster_type       = "single-node"
 }
 
```



### Secure Example

The following example will pass the aws-redshift-encryption-customer-key check.
```terraform

 resource "aws_kms_key" "redshift" {
 	enable_key_rotation = true
 }
 
 resource "aws_redshift_cluster" "good_example" {
   cluster_identifier = "tf-redshift-cluster"
   database_name      = "mydb"
   master_username    = "foo"
   master_password    = "Mustbe8characters"
   node_type          = "dc1.large"
   cluster_type       = "single-node"
   encrypted          = true
   kms_key_id         = aws_kms_key.redshift.key_id
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#encrypted](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#encrypted){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html](https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html){:target="_blank" rel="nofollow noreferrer noopener"}




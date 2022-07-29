---
title: DAX Cluster and tables should always encrypt data at rest
---

# DAX Cluster and tables should always encrypt data at rest

### Default Severity: <span class="severity high">high</span>

### Explanation

Amazon DynamoDB Accelerator (DAX) and table encryption at rest provides an additional layer of data protection by helping secure your data from unauthorized access to the underlying storage.

### Possible Impact
Data can be freely read if compromised

### Suggested Resolution
Enable encryption at rest for DAX Cluster


### Insecure Example

The following example will fail the aws-dynamodb-enable-at-rest-encryption check.
```terraform

 resource "aws_dax_cluster" "bad_example" {
 	// no server side encryption at all
 }
 
 resource "aws_dax_cluster" "bad_example" {
 	// other DAX config
 
 	server_side_encryption {
 		// empty server side encryption config
 	}
 }
 
 resource "aws_dax_cluster" "bad_example" {
 	// other DAX config
 
 	server_side_encryption {
 		enabled = false // disabled server side encryption
 	}
 }
 
```



### Secure Example

The following example will pass the aws-dynamodb-enable-at-rest-encryption check.
```terraform

 resource "aws_dax_cluster" "good_example" {
 	// other DAX config
 
 	server_side_encryption {
 		enabled = true // enabled server side encryption
 	}
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dax_cluster#server_side_encryption](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dax_cluster#server_side_encryption){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dax-cluster.html](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dax-cluster.html){:target="_blank" rel="nofollow noreferrer noopener"}




---
title: Redshift cluster should be deployed into a specific VPC
---

# Redshift cluster should be deployed into a specific VPC

### Default Severity: <span class="severity high">high</span>

### Explanation

Redshift clusters that are created without subnet details will be created in EC2 classic mode, meaning that they will be outside of a known VPC and running in tenant.

In order to benefit from the additional security features achieved with using an owned VPC, the subnet should be set.

### Possible Impact
Redshift cluster does not benefit from VPC security if it is deployed in EC2 classic mode

### Suggested Resolution
Deploy Redshift cluster into a non default VPC


### Insecure Example

The following example will fail the aws-redshift-use-vpc check.
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

The following example will pass the aws-redshift-use-vpc check.
```terraform

 resource "aws_redshift_cluster" "good_example" {
 	cluster_identifier = "tf-redshift-cluster"
 	database_name      = "mydb"
 	master_username    = "foo"
 	master_password    = "Mustbe8characters"
 	node_type          = "dc1.large"
 	cluster_type       = "single-node"
 
 	cluster_subnet_group_name = "redshift_subnet"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#cluster_subnet_group_name](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#cluster_subnet_group_name){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html](https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html){:target="_blank" rel="nofollow noreferrer noopener"}




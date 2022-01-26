---
title: EKS Clusters should have the public access disabled
---

# EKS Clusters should have the public access disabled

### Default Severity: <span class="severity critical">critical</span>

### Explanation

EKS clusters are available publicly by default, this should be explicitly disabled in the vpc_config of the EKS cluster resource.

### Possible Impact
EKS can be access from the internet

### Suggested Resolution
Don't enable public access to EKS Clusters


### Insecure Example

The following example will fail the aws-eks-no-public-cluster-access check.
```terraform

 resource "aws_eks_cluster" "bad_example" {
     // other config 
 
     name = "bad_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
 		endpoint_public_access = true
 		public_access_cidrs = ["0.0.0.0/0"]
     }
 }
 
```



### Secure Example

The following example will pass the aws-eks-no-public-cluster-access check.
```terraform

 resource "aws_eks_cluster" "good_example" {
     // other config 
 
     name = "good_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = false
     }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#endpoint_public_access](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#endpoint_public_access){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html){:target="_blank" rel="nofollow noreferrer noopener"}




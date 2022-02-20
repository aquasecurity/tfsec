---
title: EKS cluster should not have open CIDR range for public access
---

# EKS cluster should not have open CIDR range for public access

### Default Severity: <span class="severity critical">critical</span>

### Explanation

EKS Clusters have public access cidrs set to 0.0.0.0/0 by default which is wide open to the internet. This should be explicitly set to a more specific private CIDR range

### Possible Impact
EKS can be accessed from the internet

### Suggested Resolution
Don't enable public access to EKS Clusters


### Insecure Example

The following example will fail the aws-eks-no-public-cluster-access-to-cidr check.
```terraform

 resource "aws_eks_cluster" "bad_example" {
     // other config 
 
     name = "bad_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = true
     }
 }
 
```



### Secure Example

The following example will pass the aws-eks-no-public-cluster-access-to-cidr check.
```terraform

 resource "aws_eks_cluster" "good_example" {
     // other config 
 
     name = "good_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = true
         public_access_cidrs = ["10.2.0.0/8"]
     }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#vpc_config](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#vpc_config){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/eks/latest/userguide/create-public-private-vpc.html](https://docs.aws.amazon.com/eks/latest/userguide/create-public-private-vpc.html){:target="_blank" rel="nofollow noreferrer noopener"}




---
title: EKS should have the encryption of secrets enabled
---

# EKS should have the encryption of secrets enabled

### Default Severity: <span class="severity high">high</span>

### Explanation

EKS cluster resources should have the encryption_config block set with protection of the secrets resource.

### Possible Impact
EKS secrets could be read if compromised

### Suggested Resolution
Enable encryption of EKS secrets


### Insecure Example

The following example will fail the aws-eks-encrypt-secrets check.
```terraform

 resource "aws_eks_cluster" "bad_example" {
     name = "bad_example_cluster"
 
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = false
     }
 }
 
```



### Secure Example

The following example will pass the aws-eks-encrypt-secrets check.
```terraform

 resource "aws_eks_cluster" "good_example" {
     encryption_config {
         resources = [ "secrets" ]
         provider {
             key_arn = var.kms_arn
         }
     }
 
     name = "good_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = false
     }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#encryption_config](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#encryption_config){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://aws.amazon.com/about-aws/whats-new/2020/03/amazon-eks-adds-envelope-encryption-for-secrets-with-aws-kms/](https://aws.amazon.com/about-aws/whats-new/2020/03/amazon-eks-adds-envelope-encryption-for-secrets-with-aws-kms/){:target="_blank" rel="nofollow noreferrer noopener"}




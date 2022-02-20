---
title: EKS Clusters should have cluster control plane logging turned on
---

# EKS Clusters should have cluster control plane logging turned on

### Default Severity: <span class="severity medium">medium</span>

### Explanation

By default cluster control plane logging is not turned on. Logging is available for audit, api, authenticator, controllerManager and scheduler. All logging should be turned on for cluster control plane.

### Possible Impact
Logging provides valuable information about access and usage

### Suggested Resolution
Enable logging for the EKS control plane


### Insecure Example

The following example will fail the aws-eks-enable-control-plane-logging check.
```terraform

 resource "aws_eks_cluster" "bad_example" {
     encryption_config {
         resources = [ "secrets" ]
         provider {
             key_arn = var.kms_arn
         }
     }
 
     name = "bad_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = false
     }
 }
 
```



### Secure Example

The following example will pass the aws-eks-enable-control-plane-logging check.
```terraform

 resource "aws_eks_cluster" "good_example" {
     encryption_config {
         resources = [ "secrets" ]
         provider {
             key_arn = var.kms_arn
         }
     }
 
 	enabled_cluster_log_types = ["api", "authenticator", "audit", "scheduler", "controllerManager"]
 
     name = "good_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = false
     }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#enabled_cluster_log_types](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#enabled_cluster_log_types){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html){:target="_blank" rel="nofollow noreferrer noopener"}




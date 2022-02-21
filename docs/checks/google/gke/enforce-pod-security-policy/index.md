---
title: Pod security policy enforcement not defined.
---

# Pod security policy enforcement not defined.

### Default Severity: <span class="severity high">high</span>

### Explanation

By default, Pods in Kubernetes can operate with capabilities beyond what they require. You should constrain the Pod's capabilities to only those required for that workload.

Kubernetes offers controls for restricting your Pods to execute with only explicitly granted capabilities. 

Pod Security Policy allows you to set smart defaults for your Pods, and enforce controls you want to enable across your fleet. 

The policies you define should be specific to the needs of your application

### Possible Impact
Pods could be operating with more permissions than required to be effective

### Suggested Resolution
Use security policies for pods to restrict permissions to those needed to be effective


### Insecure Example

The following example will fail the google-gke-enforce-pod-security-policy check.
```terraform

 resource "google_container_cluster" "bad_example" {
 	pod_security_policy_config {
         enabled = "false"
 	}
 }
```



### Secure Example

The following example will pass the google-gke-enforce-pod-security-policy check.
```terraform

 resource "google_container_cluster" "good_example" {
 	pod_security_policy_config {
         enabled = "true"
 	}
 }
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#pod_security_policy_config](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#pod_security_policy_config){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#admission_controllers](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#admission_controllers){:target="_blank" rel="nofollow noreferrer noopener"}




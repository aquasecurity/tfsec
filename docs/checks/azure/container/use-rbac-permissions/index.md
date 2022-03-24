---
title: Ensure RBAC is enabled on AKS clusters
---

# Ensure RBAC is enabled on AKS clusters

### Default Severity: <span class="severity high">high</span>

### Explanation

Using Kubernetes role-based access control (RBAC), you can grant users, groups, and service accounts access to only the resources they need.

### Possible Impact
No role based access control is in place for the AKS cluster

### Suggested Resolution
Enable RBAC


### Insecure Example

The following example will fail the azure-container-use-rbac-permissions check.
```terraform

 resource "azurerm_kubernetes_cluster" "bad_example" {
	// azurerm < 2.99.0
 	role_based_access_control {
 		enabled = false
 	}

	// azurerm >= 2.99.0
	role_based_access_control_enabled = false
 }
 
```



### Secure Example

The following example will pass the azure-container-use-rbac-permissions check.
```terraform

 resource "azurerm_kubernetes_cluster" "good_example" {
	// azurerm < 2.99.0
	role_based_access_control {
 		enabled = true
 	}

	// azurerm >= 2.99.0
 	role_based_access_control_enabled = true
 }
 
```



### Links


- [https://www.terraform.io/docs/providers/azurerm/r/kubernetes_cluster.html#role_based_access_control](https://www.terraform.io/docs/providers/azurerm/r/kubernetes_cluster.html#role_based_access_control){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/aks/concepts-identity](https://docs.microsoft.com/en-us/azure/aks/concepts-identity){:target="_blank" rel="nofollow noreferrer noopener"}




---
title: Ensure AKS has an API Server Authorized IP Ranges enabled
---

# Ensure AKS has an API Server Authorized IP Ranges enabled

### Default Severity: <span class="severity critical">critical</span>

### Explanation

The API server is the central way to interact with and manage a cluster. To improve cluster security and minimize attacks, the API server should only be accessible from a limited set of IP address ranges.

### Possible Impact
Any IP can interact with the API server

### Suggested Resolution
Limit the access to the API server to a limited IP range


### Insecure Example

The following example will fail the azure-container-limit-authorized-ips check.
```terraform

 resource "azurerm_kubernetes_cluster" "bad_example" {
 
 }
 
```



### Secure Example

The following example will pass the azure-container-limit-authorized-ips check.
```terraform

 resource "azurerm_kubernetes_cluster" "good_example" {
     api_server_authorized_ip_ranges = [
 		"1.2.3.4/32"
 	]
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#api_server_authorized_ip_ranges](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#api_server_authorized_ip_ranges){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges](https://docs.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges){:target="_blank" rel="nofollow noreferrer noopener"}




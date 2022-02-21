---
title: Ensure AKS logging to Azure Monitoring is Configured
---

# Ensure AKS logging to Azure Monitoring is Configured

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Ensure AKS logging to Azure Monitoring is configured for containers to monitor the performance of workloads.

### Possible Impact
Logging provides valuable information about access and usage

### Suggested Resolution
Enable logging for AKS


### Insecure Example

The following example will fail the azure-container-logging check.
```terraform

 resource "azurerm_kubernetes_cluster" "bad_example" {
     addon_profile {}
 }
 
```



### Secure Example

The following example will pass the azure-container-logging check.
```terraform

 resource "azurerm_kubernetes_cluster" "good_example" {
     addon_profile {
 		oms_agent {
 			enabled = true
 		}
 	}
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#oms_agent](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#oms_agent){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-onboard](https://docs.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-onboard){:target="_blank" rel="nofollow noreferrer noopener"}




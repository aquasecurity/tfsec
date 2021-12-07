---
title: defender-on-kubernetes
---

### Explanation

Azure Defender is a cloud workload protection service that utilizes and agent-based deployment to analyze signals from Azure network fabric and the service control plane, to detect threats across all Azure resources. It can also analyze non-Azure resources, utilizing Azure Arc, including those on-premises and in both AWS and GCP (once they've been onboarded).
			Azure Defender for Kubernetes provides cluster-level threat protection by monitoring your AKS-managed services through the logs retrieved by Azure Kubernetes Service (AKS).

### Possible Impact
Not enabling defender for container registries could lead to compromised account

### Suggested Resolution
Enable KubernetesService in Azure Defender


### Insecure Example

The following example will fail the azure-security-center-defender-on-kubernetes check.

```terraform

resource "azurerm_security_center_subscription_pricing" "bad_example" {
  tier          = "Free"
  resource_type = "VirtualMachines"
}

```



### Secure Example

The following example will pass the azure-security-center-defender-on-kubernetes check.

```terraform

resource "azurerm_security_center_subscription_pricing" "good_example" {
  tier          = "Standard"
  resource_type = "VirtualMachines,KubernetesService"
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#resource_type](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#resource_type){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/security-center/defender-for-kubernetes-introduction](https://docs.microsoft.com/en-us/azure/security-center/defender-for-kubernetes-introduction){:target="_blank" rel="nofollow noreferrer noopener"}



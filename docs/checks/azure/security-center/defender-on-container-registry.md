---
title: defender-on-container-registry
---

### Explanation

Azure Defender is a cloud workload protection service that utilizes and agent-based deployment to analyze signals from Azure network fabric and the service control plane, to detect threats across all Azure resources. It can also analyze non-Azure resources, utilizing Azure Arc, including those on-premises and in both AWS and GCP (once they've been onboarded).
			Azure Defender for container registries includes a vulnerability scanner to scan the images in Azure Resource Manager-based Azure Container Registry registries and provide deeper visibility image vulnerabilities.

### Possible Impact
Not enabling defender for container registries could lead to compromised account

### Suggested Resolution
Enable ContainerRegistry in Azure Defender


### Insecure Example

The following example will fail the azure-security-center-defender-on-container-registry check.

```terraform

resource "azurerm_security_center_subscription_pricing" "bad_example" {
  tier          = "Free"
  resource_type = "VirtualMachines"
}

```



### Secure Example

The following example will pass the azure-security-center-defender-on-container-registry check.

```terraform

resource "azurerm_security_center_subscription_pricing" "good_example" {
  tier          = "Standard"
  resource_type = "VirtualMachines,ContainerRegistry"
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#resource_type](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#resource_type){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/security-center/defender-for-container-registries-introduction](https://docs.microsoft.com/en-us/azure/security-center/defender-for-container-registries-introduction){:target="_blank" rel="nofollow noreferrer noopener"}



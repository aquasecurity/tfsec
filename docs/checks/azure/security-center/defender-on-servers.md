---
title: defender-on-servers
---

### Explanation

Azure Defender is a cloud workload protection service that utilizes and agent-based deployment to analyze signals from Azure network fabric and the service control plane, to detect threats across all Azure resources. It can also analyze non-Azure resources, utilizing Azure Arc, including those on-premises and in both AWS and GCP (once they've been onboarded).

### Possible Impact
Azure Defender for servers adds threat detection and advanced defenses for Windows and Linux machines.

### Suggested Resolution
Enable VirtualMachines in Azure Defender


### Insecure Example

The following example will fail the azure-security-center-defender-on-servers check.

```terraform

resource "azurerm_security_center_subscription_pricing" "bad_example" {
  tier          = "Free"
  resource_type = "AppServices"
}

```



### Secure Example

The following example will pass the azure-security-center-defender-on-servers check.

```terraform

resource "azurerm_security_center_subscription_pricing" "good_example" {
  tier          = "Standard"
  resource_type = "AppServices,VirtualMachines"
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#resource_type](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#resource_type){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/security-center/defender-for-servers-introduction](https://docs.microsoft.com/en-us/azure/security-center/defender-for-servers-introduction){:target="_blank" rel="nofollow noreferrer noopener"}



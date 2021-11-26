---
title: defender-on-storage
---

### Explanation

Azure Defender is a cloud workload protection service that utilizes and agent-based deployment to analyze signals from Azure network fabric and the service control plane, to detect threats across all Azure resources. It can also analyze non-Azure resources, utilizing Azure Arc, including those on-premises and in both AWS and GCP (once they've been onboarded).

### Possible Impact
Azure Defender for Storage detects unusual and potentially harmful attempts to access or exploit storage accounts.

### Suggested Resolution
Enable StorageAccounts in Azure Defender


### Insecure Example

The following example will fail the azure-security-center-defender-on-storage check.

```terraform

resource "azurerm_security_center_subscription_pricing" "bad_example" {
  tier          = "Free"
  resource_type = "VirtualMachines"
}

```



### Secure Example

The following example will pass the azure-security-center-defender-on-storage check.

```terraform

resource "azurerm_security_center_subscription_pricing" "good_example" {
  tier          = "Standard"
  resource_type = "VirtualMachines,StorageAccounts"
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#resource_type](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#resource_type){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/security-center/defender-for-storage-introduction](https://docs.microsoft.com/en-us/azure/security-center/defender-for-storage-introduction){:target="_blank" rel="nofollow noreferrer noopener"}



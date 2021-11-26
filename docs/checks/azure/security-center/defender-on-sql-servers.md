---
title: defender-on-sql-servers
---

### Explanation

Azure Defender is a cloud workload protection service that utilizes and agent-based deployment to analyze signals from Azure network fabric and the service control plane, to detect threats across all Azure resources. It can also analyze non-Azure resources, utilizing Azure Arc, including those on-premises and in both AWS and GCP (once they've been onboarded).

### Possible Impact
Azure Defender for SQL servers on machines extends the protections for your Azure-native SQL Servers to fully support hybrid environments and protect SQL servers (all supported version) hosted in Azure

### Suggested Resolution
Enable SqlServers in Azure Defender


### Insecure Example

The following example will fail the azure-security-center-defender-on-sql-servers check.

```terraform

resource "azurerm_security_center_subscription_pricing" "bad_example" {
  tier          = "Free"
  resource_type = "VirtualMachines"
}

```



### Secure Example

The following example will pass the azure-security-center-defender-on-sql-servers check.

```terraform

resource "azurerm_security_center_subscription_pricing" "good_example" {
  tier          = "Standard"
  resource_type = "VirtualMachines,SqlServers"
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#resource_type](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#resource_type){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/security-center/defender-for-sql-introduction](https://docs.microsoft.com/en-us/azure/security-center/defender-for-sql-introduction){:target="_blank" rel="nofollow noreferrer noopener"}



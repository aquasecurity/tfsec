---
title: Enable the standard security center subscription tier
---

# Enable the standard security center subscription tier

### Default Severity: <span class="severity low">low</span>

### Explanation

To benefit from Azure Defender you should use the Standard subscription tier.
			
			Enabling Azure Defender extends the capabilities of the free mode to workloads running in private and other public clouds, providing unified security management and threat protection across your hybrid cloud workloads.

### Possible Impact
Using free subscription does not enable Azure Defender for the resource type

### Suggested Resolution
Enable standard subscription tier to benefit from Azure Defender


### Insecure Example

The following example will fail the azure-security-center-enable-standard-subscription check.
```terraform

 resource "azurerm_security_center_subscription_pricing" "bad_example" {
   tier          = "Free"
   resource_type = "VirtualMachines"
 }
 
```



### Secure Example

The following example will pass the azure-security-center-enable-standard-subscription check.
```terraform

 resource "azurerm_security_center_subscription_pricing" "good_example" {
   tier          = "Standard"
   resource_type = "VirtualMachines"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#tier](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#tier){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/security-center/security-center-pricing](https://docs.microsoft.com/en-us/azure/security-center/security-center-pricing){:target="_blank" rel="nofollow noreferrer noopener"}




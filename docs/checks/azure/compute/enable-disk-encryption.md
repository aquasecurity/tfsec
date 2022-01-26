---
title: Enable disk encryption on managed disk
---

# Enable disk encryption on managed disk

### Default Severity: <span class="severity high">high</span>

### Explanation

Manage disks should be encrypted at rest. When specifying the <code>encryption_settings</code> block, the enabled attribute should be set to <code>true</code>.

### Possible Impact
Data could be read if compromised

### Suggested Resolution
Enable encryption on managed disks


### Insecure Example

The following example will fail the azure-compute-enable-disk-encryption check.
```terraform

 resource "azurerm_managed_disk" "bad_example" {
 	encryption_settings {
 		enabled = false
 	}
 }
```



### Secure Example

The following example will pass the azure-compute-enable-disk-encryption check.
```terraform

 resource "azurerm_managed_disk" "good_example" {
 	encryption_settings {
 		enabled = true
 	}
 }
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption){:target="_blank" rel="nofollow noreferrer noopener"}




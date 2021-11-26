---
title: ssh-authentication
---

### Explanation


Access to instances should be authenticated using SSH keys. Removing the option of password authentication enforces more secure methods while removing the risks inherent with passwords.


### Possible Impact
Passwords are potentially easier to compromise than SSH Keys

### Suggested Resolution
Use SSH keys for authentication


### Insecure Example

The following example will fail the azure-compute-ssh-authentication check.

```terraform

resource "azurerm_virtual_machine" "bad_example" {
	os_profile_linux_config {
		disable_password_authentication = false
	}
}
```



### Secure Example

The following example will pass the azure-compute-ssh-authentication check.

```terraform

resource "azurerm_virtual_machine" "good_example" {
	os_profile_linux_config {
		disable_password_authentication = true
	}
}
```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/virtual-machines/linux/create-ssh-keys-detailed](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/create-ssh-keys-detailed){:target="_blank" rel="nofollow noreferrer noopener"}



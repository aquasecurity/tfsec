---
title: Ensure that no sensitive credentials are exposed in VM custom_data
---

# Ensure that no sensitive credentials are exposed in VM custom_data

### Default Severity: <span class="severity medium">medium</span>

### Explanation

When creating Azure Virtual Machines, custom_data is used to pass start up information into the EC2 instance. This custom_dat must not contain access key credentials.

### Possible Impact
Sensitive credentials in custom_data can be leaked

### Suggested Resolution
Don't use sensitive credentials in the VM custom_data


### Insecure Example

The following example will fail the azure-compute-no-secrets-in-custom-data check.
```terraform

 resource "azurerm_virtual_machine" "bad_example" {
 	name = "bad_example"
	os_profile_linux_config {
		disable_password_authentication = false
	}
	os_profile {
		custom_data =<<EOF
			export DATABASE_PASSWORD=\"SomeSortOfPassword\"
			EOF
	}
 }
 
```



### Secure Example

The following example will pass the azure-compute-no-secrets-in-custom-data check.
```terraform

 resource "azurerm_virtual_machine" "good_example" {
 	name = "good_example"
	os_profile_linux_config {
		disable_password_authentication = false
	}
	os_profile {
		custom_data =<<EOF
			export GREETING="Hello there"
			EOF
	}
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#custom_data](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#custom_data){:target="_blank" rel="nofollow noreferrer noopener"}




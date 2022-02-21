---
title: Password authentication should be disabled on Azure virtual machines
---

# Password authentication should be disabled on Azure virtual machines

### Default Severity: <span class="severity high">high</span>

### Explanation

Access to virtual machines should be authenticated using SSH keys. Removing the option of password authentication enforces more secure methods while removing the risks inherent with passwords.

### Possible Impact
Using password authentication is less secure that ssh keys may result in compromised servers

### Suggested Resolution
Use ssh authentication for virtual machines


### Insecure Example

The following example will fail the azure-compute-disable-password-authentication check.
```terraform

 resource "azurerm_linux_virtual_machine" "bad_linux_example" {
   name                            = "bad-linux-machine"
   resource_group_name             = azurerm_resource_group.example.name
   location                        = azurerm_resource_group.example.location
   size                            = "Standard_F2"
   admin_username                  = "adminuser"
   admin_password                  = "somePassword"
   disable_password_authentication = false
 }
 
 resource "azurerm_virtual_machine" "bad_example" {
 	name                            = "bad-linux-machine"
 	resource_group_name             = azurerm_resource_group.example.name
 	location                        = azurerm_resource_group.example.location
 	size                            = "Standard_F2"
 	admin_username                  = "adminuser"
 	admin_password                  = "somePassword"
 
 	os_profile {
 		computer_name  = "hostname"
 		admin_username = "testadmin"
 		admin_password = "Password1234!"
 	}
 
 	os_profile_linux_config {
 		disable_password_authentication = false
 	}
   }
 
```



### Secure Example

The following example will pass the azure-compute-disable-password-authentication check.
```terraform

 resource "azurerm_linux_virtual_machine" "good_linux_example" {
   name                            = "good-linux-machine"
   resource_group_name             = azurerm_resource_group.example.name
   location                        = azurerm_resource_group.example.location
   size                            = "Standard_F2"
   admin_username                  = "adminuser"
   admin_password                  = "somePassword"
   
   admin_ssh_key {
     username   = "adminuser"
     public_key = file("~/.ssh/id_rsa.pub")
   }
 }
 
 resource "azurerm_virtual_machine" "good_example" {
 	name                            = "good-linux-machine"
 	resource_group_name             = azurerm_resource_group.example.name
 	location                        = azurerm_resource_group.example.location
 	size                            = "Standard_F2"
 	admin_username                  = "adminuser"
 
 	
 	os_profile_linux_config {
 		ssh_keys = [{
 			key_data = file("~/.ssh/id_rsa.pub")
 			path = "~/.ssh/id_rsa.pub"
 		}]
 
 		disable_password_authentication = true
 	}
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine#disable_password_authentication](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine#disable_password_authentication){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#disable_password_authentication](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#disable_password_authentication){:target="_blank" rel="nofollow noreferrer noopener"}




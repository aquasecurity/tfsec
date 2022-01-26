---
title: RDP access should not be accessible from the Internet, should be blocked on port 3389
---

# RDP access should not be accessible from the Internet, should be blocked on port 3389

### Default Severity: <span class="severity critical">critical</span>

### Explanation

RDP access can be configured on either the network security group or in the network security group rule.

RDP access should not be permitted from the internet (*, 0.0.0.0, /0, internet, any). Consider using the Azure Bastion Service.

### Possible Impact
Anyone from the internet can potentially RDP onto an instance

### Suggested Resolution
Block RDP port from internet


### Insecure Example

The following example will fail the azure-network-disable-rdp-from-internet check.
```terraform

 resource "azurerm_network_security_rule" "bad_example" {
      name                        = "bad_example_security_rule"
      direction                   = "Inbound"
      access                      = "Allow"
      protocol                    = "TCP"
      source_port_range           = "*"
      destination_port_ranges     = ["3389"]
      source_address_prefix       = "*"
      destination_address_prefix  = "*"
 }
 
 resource "azurerm_network_security_group" "example" {
   name                = "tf-appsecuritygroup"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   
   security_rule {
 	 source_port_range           = "any"
      destination_port_ranges     = ["3389"]
      source_address_prefix       = "*"
      destination_address_prefix  = "*"
   }
 }
 
```



### Secure Example

The following example will pass the azure-network-disable-rdp-from-internet check.
```terraform

 resource "azurerm_network_security_rule" "good_example" {
      name                        = "good_example_security_rule"
      direction                   = "Inbound"
      access                      = "Allow"
      protocol                    = "TCP"
      source_port_range           = "*"
      destination_port_ranges     = ["3389"]
      source_address_prefix       = "4.53.160.75"
      destination_address_prefix  = "*"
 }
 
 resource "azurerm_network_security_group" "example" {
   name                = "tf-appsecuritygroup"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   
   security_rule {
 	 source_port_range           = "any"
      destination_port_ranges     = ["3389"]
      source_address_prefix       = "4.53.160.75"
      destination_address_prefix  = "*"
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/network_security_group#security_rule](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/network_security_group#security_rule){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#source_port_ranges](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#source_port_ranges){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/bastion/tutorial-create-host-portal](https://docs.microsoft.com/en-us/azure/bastion/tutorial-create-host-portal){:target="_blank" rel="nofollow noreferrer noopener"}




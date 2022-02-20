---
title: SSH access should not be accessible from the Internet, should be blocked on port 22
---

# SSH access should not be accessible from the Internet, should be blocked on port 22

### Default Severity: <span class="severity critical">critical</span>

### Explanation

SSH access can be configured on either the network security group or in the network security group rule. 

SSH access should not be permitted from the internet (*, 0.0.0.0, /0, internet, any)

### Possible Impact
Its dangerous to allow SSH access from the internet

### Suggested Resolution
Block port 22 access from the internet


### Insecure Example

The following example will fail the azure-network-ssh-blocked-from-internet check.
```terraform

 resource "azurerm_network_security_rule" "bad_example" {
      name                        = "bad_example_security_rule"
      direction                   = "Inbound"
      access                      = "Allow"
      protocol                    = "TCP"
      source_port_range           = "*"
      destination_port_range      = "22"
      source_address_prefix       = "*"
      destination_address_prefix  = "*"
 }
 
```



### Secure Example

The following example will pass the azure-network-ssh-blocked-from-internet check.
```terraform

 resource "azurerm_network_security_rule" "good_example" {
      name                        = "good_example_security_rule"
      direction                   = "Inbound"
      access                      = "Allow"
      protocol                    = "TCP"
      source_port_range           = "*"
      destination_port_range      = "22"
      source_address_prefix       = "82.102.23.23"
      destination_address_prefix  = "*"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/network_security_group#security_rule](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/network_security_group#security_rule){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#source_port_ranges](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#source_port_ranges){:target="_blank" rel="nofollow noreferrer noopener"}




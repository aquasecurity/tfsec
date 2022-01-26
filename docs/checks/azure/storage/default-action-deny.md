---
title: The default action on Storage account network rules should be set to deny
---

# The default action on Storage account network rules should be set to deny

### Default Severity: <span class="severity critical">critical</span>

### Explanation

The default_action for network rules should come into effect when no other rules are matched.

The default action should be set to Deny.

### Possible Impact
Network rules that allow could cause data to be exposed publicly

### Suggested Resolution
Set network rules to deny


### Insecure Example

The following example will fail the azure-storage-default-action-deny check.
```terraform

 resource "azurerm_storage_account_network_rules" "bad_example" {
   
   default_action             = "Allow"
   ip_rules                   = ["127.0.0.1"]
   virtual_network_subnet_ids = [azurerm_subnet.test.id]
   bypass                     = ["Metrics"]
 }
 
```



### Secure Example

The following example will pass the azure-storage-default-action-deny check.
```terraform

 resource "azurerm_storage_account_network_rules" "good_example" {
   
   default_action             = "Deny"
   ip_rules                   = ["127.0.0.1"]
   virtual_network_subnet_ids = [azurerm_subnet.test.id]
   bypass                     = ["Metrics"]
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#default_action](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#default_action){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/firewall/rule-processing](https://docs.microsoft.com/en-us/azure/firewall/rule-processing){:target="_blank" rel="nofollow noreferrer noopener"}




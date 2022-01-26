---
title: Retention policy for flow logs should be enabled and set to greater than 90 days
---

# Retention policy for flow logs should be enabled and set to greater than 90 days

### Default Severity: <span class="severity low">low</span>

### Explanation

Flow logs are the source of truth for all network activity in your cloud environment. 
To enable analysis in security event that was detected late, you need to have the logs available. 
			
Setting an retention policy will help ensure as much information is available for review.

### Possible Impact
Not enabling retention or having short expiry on flow logs could lead to compromise being undetected limiting time for analysis

### Suggested Resolution
Ensure flow log retention is turned on with an expiry of >90 days


### Insecure Example

The following example will fail the azure-network-retention-policy-set check.
```terraform

resource "azurerm_network_watcher_flow_log" "bad_watcher" {
	network_watcher_name = "bad_watcher"
	resource_group_name = "resource-group"

	network_security_group_id = azurerm_network_security_group.test.id
	storage_account_id = azurerm_storage_account.test.id
	enabled = true

	retention_policy {
		enabled = true
		days = 7
	}
}
		
```



### Secure Example

The following example will pass the azure-network-retention-policy-set check.
```terraform

resource "azurerm_network_watcher_flow_log" "good_watcher" {
	network_watcher_name = "good_watcher"
	resource_group_name = "resource-group"

	network_security_group_id = azurerm_network_security_group.test.id
	storage_account_id = azurerm_storage_account.test.id
	enabled = true

	retention_policy {
		enabled = true
		days = 90
	}
}
	
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_watcher_flow_log#retention_policy](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_watcher_flow_log#retention_policy){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview](https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview){:target="_blank" rel="nofollow noreferrer noopener"}




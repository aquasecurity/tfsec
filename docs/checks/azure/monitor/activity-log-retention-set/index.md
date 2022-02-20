---
title: Ensure the activity retention log is set to at least a year
---

# Ensure the activity retention log is set to at least a year

### Default Severity: <span class="severity medium">medium</span>

### Explanation

The average time to detect a breach is up to 210 days, to ensure that all the information required for an effective investigation is available, the retention period should allow for delayed starts to investigating.

### Possible Impact
Short life activity logs can lead to missing records when investigating a breach

### Suggested Resolution
Set a retention period that will allow for delayed investigation


### Insecure Example

The following example will fail the azure-monitor-activity-log-retention-set check.
```terraform

 resource "azurerm_monitor_log_profile" "bad_example" {
   name = "bad_example"
 
   retention_policy {
     enabled = true
     days    = 7
   }
 }
 
```



### Secure Example

The following example will pass the azure-monitor-activity-log-retention-set check.
```terraform

 resource "azurerm_monitor_log_profile" "good_example" {
   name = "good_example"
 
   retention_policy {
     enabled = true
     days    = 365
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile#retention_policy](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile#retention_policy){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/platform-logs-overview](https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/platform-logs-overview){:target="_blank" rel="nofollow noreferrer noopener"}




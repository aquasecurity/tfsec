---
title: Ensure log profile captures all activities
---

# Ensure log profile captures all activities

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Log profiles should capture all categories to ensure that all events are logged

### Possible Impact
Log profile must capture all activity to be able to ensure that all relevant information possible is available for an investigation

### Suggested Resolution
Configure log profile to capture all activities


### Insecure Example

The following example will fail the azure-monitor-capture-all-activities check.
```terraform

 resource "azurerm_monitor_log_profile" "bad_example" {
   name = "bad_example"
 
   categories = []
 
   retention_policy {
     enabled = true
     days    = 7
   }
 }
 
```



### Secure Example

The following example will pass the azure-monitor-capture-all-activities check.
```terraform

 resource "azurerm_monitor_log_profile" "good_example" {
   name = "good_example"
 
   categories = [
 	  "Action",
 	  "Delete",
 	  "Write",
   ]
 
   retention_policy {
     enabled = true
     days    = 365
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile#categories](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile#categories){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log](https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/cli/azure/monitor/log-profiles?view=azure-cli-latest#az_monitor_log_profiles_create-required-parameters](https://docs.microsoft.com/en-us/cli/azure/monitor/log-profiles?view=azure-cli-latest#az_monitor_log_profiles_create-required-parameters){:target="_blank" rel="nofollow noreferrer noopener"}




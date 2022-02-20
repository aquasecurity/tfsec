---
title: Send notification emails for high severity alerts
---

# Send notification emails for high severity alerts

### Default Severity: <span class="severity medium">medium</span>

### Explanation

It is recommended that at least one valid contact is configured for the security center. 
Microsoft will notify the security contact directly in the event of a security incident using email and require alerting to be turned on.

### Possible Impact
The ability to react to high severity notifications could be delayed

### Suggested Resolution
 Set alert notifications to be on


### Insecure Example

The following example will fail the azure-security-center-alert-on-severe-notifications check.
```terraform

		resource "azurerm_security_center_contact" "bad_example" {
		email = "bad_example@example.com"
		phone = "+1-555-555-5555"

		alert_notifications = false
		alerts_to_admins = false
		}
		
```



### Secure Example

The following example will pass the azure-security-center-alert-on-severe-notifications check.
```terraform

		resource "azurerm_security_center_contact" "good_example" {
		email = "good_example@example.com"
		phone = "+1-555-555-5555"

		alert_notifications = true
		alerts_to_admins = true
		}
	
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#alert_notifications](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#alert_notifications){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://azure.microsoft.com/en-us/services/security-center/](https://azure.microsoft.com/en-us/services/security-center/){:target="_blank" rel="nofollow noreferrer noopener"}




---
title: set-required-contact-details
---

### Explanation

It is recommended that at least one valid contact is configured for the security center. 
Microsoft will notify the security contact directly in the event of a security incident and will look to use a telephone number in cases where a prompt response is required.

### Possible Impact
Without a telephone number set, Azure support can't contact

### Suggested Resolution
Set a telephone number for security center contact


### Insecure Example

The following example will fail the azure-security-center-set-required-contact-details check.

```terraform

resource "azurerm_security_center_contact" "bad_example" {
  email = "bad_contact@example.com"
  phone = ""

  alert_notifications = true
  alerts_to_admins    = true
}

```



### Secure Example

The following example will pass the azure-security-center-set-required-contact-details check.

```terraform

resource "azurerm_security_center_contact" "good_example" {
  email = "good_contact@example.com"
  phone = "+1-555-555-5555"

  alert_notifications = true
  alerts_to_admins    = true
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#phone](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#phone){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#email](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#email){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://azure.microsoft.com/en-us/services/security-center/](https://azure.microsoft.com/en-us/services/security-center/){:target="_blank" rel="nofollow noreferrer noopener"}



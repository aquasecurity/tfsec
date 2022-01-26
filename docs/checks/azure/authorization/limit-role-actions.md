---
title: Roles limited to the required actions
---

# Roles limited to the required actions

### Default Severity: <span class="severity medium">medium</span>

### Explanation

The permissions granted to a role should be kept to the minimum required to be able to do the task. Wildcard permissions must not be used.

### Possible Impact
Open permissions for subscriptions could result in an easily compromisable account

### Suggested Resolution
Use targeted permissions for roles


### Insecure Example

The following example will fail the azure-authorization-limit-role-actions check.
```terraform

 data "azurerm_subscription" "primary" {
 }
 
 resource "azurerm_role_definition" "example" {
   name        = "my-custom-role"
   scope       = data.azurerm_subscription.primary.id
   description = "This is a custom role created via Terraform"
 
   permissions {
     actions     = ["*"]
     not_actions = []
   }
 
   assignable_scopes = [
     "/"
   ]
 }
 
```



### Secure Example

The following example will pass the azure-authorization-limit-role-actions check.
```terraform

 data "azurerm_subscription" "primary" {
 }
 
 resource "azurerm_role_definition" "example" {
   name        = "my-custom-role"
   scope       = data.azurerm_subscription.primary.id
   description = "This is a custom role created via Terraform"
 
   permissions {
     actions     = ["*"]
     not_actions = []
   }
 
   assignable_scopes = [
     data.azurerm_subscription.primary.id,
   ]
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_definition#actions](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_definition#actions){:target="_blank" rel="nofollow noreferrer noopener"}




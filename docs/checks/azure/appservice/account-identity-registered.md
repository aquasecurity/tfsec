---
title: Web App has registration with AD enabled
---

# Web App has registration with AD enabled

### Default Severity: <span class="severity low">low</span>

### Explanation

Registering the identity used by an App with AD allows it to interact with other services without using username and password

### Possible Impact
Interaction between services can't easily be achieved without username/password

### Suggested Resolution
Register the app identity with AD


### Insecure Example

The following example will fail the azure-appservice-account-identity-registered check.
```terraform

 resource "azurerm_app_service" "bad_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 }
 
```



### Secure Example

The following example will pass the azure-appservice-account-identity-registered check.
```terraform

 resource "azurerm_app_service" "good_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 
   identity {
     type = "UserAssigned"
     identity_ids = "webapp1"
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#identity](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#identity){:target="_blank" rel="nofollow noreferrer noopener"}




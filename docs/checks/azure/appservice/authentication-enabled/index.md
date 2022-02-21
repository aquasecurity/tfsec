---
title: App Service authentication is activated
---

# App Service authentication is activated

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Enabling authentication ensures that all communications in the application are authenticated. The auth_settings block needs to be filled out with the appropriate auth backend settings

### Possible Impact
Anonymous HTTP requests will be accepted

### Suggested Resolution
Enable authentication to prevent anonymous request being accepted


### Insecure Example

The following example will fail the azure-appservice-authentication-enabled check.
```terraform

 resource "azurerm_app_service" "bad_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 }
 
```



### Secure Example

The following example will pass the azure-appservice-authentication-enabled check.
```terraform

 resource "azurerm_app_service" "good_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 
   auth_settings {
     enabled = true
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#enabled](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#enabled){:target="_blank" rel="nofollow noreferrer noopener"}




---
title: authentication-enabled
---

### Explanation

Enabling authentication ensures that all communications in the application are authenticated. The auth_settings block needs to be filled out with the appropriate auth backend settings

### Possible Impact
Anonymous HTTP requests will be accepted

### Suggested Resolution
Enable authentication to prevent anonymous request being accepted


### Insecure Example

The following example will fail the azure-functionapp-authentication-enabled check.

```terraform

resource "azurerm_function_app" "bad_example" {
  name                = "example-function-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_function_app_plan.example.id
}

```



### Secure Example

The following example will pass the azure-functionapp-authentication-enabled check.

```terraform

resource "azurerm_function_app" "good_example" {
  name                = "example-function-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_function_app_plan.example.id

  auth_settings {
    enabled = true
  }
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#enabled](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#enabled){:target="_blank" rel="nofollow noreferrer noopener"}



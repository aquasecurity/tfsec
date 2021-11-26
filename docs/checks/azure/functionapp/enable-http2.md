---
title: enable-http2
---

### Explanation

Use the latest version of HTTP to ensure you are benefiting from security fixes

### Possible Impact
Outdated versions of HTTP has security vulnerabilities

### Suggested Resolution
Use the latest version of HTTP


### Insecure Example

The following example will fail the azure-functionapp-enable-http2 check.

```terraform

resource "azurerm_function_app" "bad_example" {
  name                = "example-function-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
}

```



### Secure Example

The following example will pass the azure-functionapp-enable-http2 check.

```terraform

resource "azurerm_function_app" "good_example" {
  name                = "example-function-app"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
  site_config {
	  http2_enabled = true
  }
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#http2_enabled](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#http2_enabled){:target="_blank" rel="nofollow noreferrer noopener"}



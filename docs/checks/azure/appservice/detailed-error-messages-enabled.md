---
title: detailed-error-messages-enabled
---

### Explanation

Copies of the .htm error pages that would have been sent to the client browser. For security reasons, detailed error pages shouldn't be sent to clients in production, but App Service can save the error page each time an application error occurs that has HTTP code 400 or greater. The page may contain information that can help determine why the server returns the error code.

### Possible Impact
Missing crucial details in the error messages

### Suggested Resolution
Enable detailed_error_messages_enabled


### Insecure Example

The following example will fail the azure-appservice-detailed-error-messages-enabled check.

```terraform

resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
}

```



### Secure Example

The following example will pass the azure-appservice-detailed-error-messages-enabled check.

```terraform

resource "azurerm_app_service" "good_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  logs {
    detailed_error_messages_enabled = true
  }
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#detailed_error_messages_enabled](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#detailed_error_messages_enabled){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs](https://docs.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs){:target="_blank" rel="nofollow noreferrer noopener"}



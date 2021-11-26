---
title: failed-request-tracing-enabled
---

### Explanation

Detailed tracing information on failed requests, including a trace of the IIS components used to process the request and the time taken in each component. It's useful if you want to improve site performance or isolate a specific HTTP error. One folder is generated for each failed request, which contains the XML log file, and the XSL stylesheet to view the log file with.

### Possible Impact
Logging of failed request tracing will not be logged

### Suggested Resolution
Enable failed_request_tracing_enabled


### Insecure Example

The following example will fail the azure-appservice-failed-request-tracing-enabled check.

```terraform

resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
}

```



### Secure Example

The following example will pass the azure-appservice-failed-request-tracing-enabled check.

```terraform

resource "azurerm_app_service" "good_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  logs {
    failed_request_tracing_enabled = true
  }
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#failed_request_tracing_enabled](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#failed_request_tracing_enabled){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs](https://docs.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs){:target="_blank" rel="nofollow noreferrer noopener"}



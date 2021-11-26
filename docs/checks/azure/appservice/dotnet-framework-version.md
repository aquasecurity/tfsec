---
title: dotnet-framework-version
---

### Explanation

Azure App Service web applications developed with the .NET software stack should use the latest available version of .NET to ensure the latest security fixes are in use.

### Possible Impact
Outdated .NET could contain open vulnerabilities

### Suggested Resolution
Use the latest version of the .NET framework


### Insecure Example

The following example will fail the azure-appservice-dotnet-framework-version check.

```terraform

resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
}

```



### Secure Example

The following example will pass the azure-appservice-dotnet-framework-version check.

```terraform

resource "azurerm_app_service" "good_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
	dotnet_framework_version = "v5.0"
  }
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#dotnet_framework_version](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#dotnet_framework_version){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/app-service/configure-language-dotnetcore](https://docs.microsoft.com/en-us/azure/app-service/configure-language-dotnetcore){:target="_blank" rel="nofollow noreferrer noopener"}



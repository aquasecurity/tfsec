---
title: python-version
---

### Explanation

Azure App Service web applications developed with the Python should use the latest available version of Python to ensure the latest security fixes are in use.

### Possible Impact
Old Python Versions can contain vulnerabilities which lead to compromised Web Applications

### Suggested Resolution
Ensure Latest Python Version is being used


### Insecure Example

The following example will fail the azure-appservice-python-version check.

```terraform

resource "azurerm_app_service" "good_example" {
	name                = "example-app-service"
	location            = azurerm_resource_group.example.location
	resource_group_name = azurerm_resource_group.example.name
	app_service_plan_id = azurerm_app_service_plan.example.id
	site_config {
	  python_version = "2.7"
	}
  }

```



### Secure Example

The following example will pass the azure-appservice-python-version check.

```terraform

resource "azurerm_app_service" "good_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
  site_config {
    python_version = "3.4"
  }
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#python_version](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#python_version){:target="_blank" rel="nofollow noreferrer noopener"}



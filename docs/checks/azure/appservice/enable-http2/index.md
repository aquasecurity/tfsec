---
title: Web App uses the latest HTTP version
---

# Web App uses the latest HTTP version

### Default Severity: <span class="severity low">low</span>

### Explanation

Use the latest version of HTTP to ensure you are benefiting from security fixes

### Possible Impact
Outdated versions of HTTP has security vulnerabilities

### Suggested Resolution
Use the latest version of HTTP


### Insecure Example

The following example will fail the azure-appservice-enable-http2 check.
```terraform

 resource "azurerm_app_service" "bad_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 }
 
```



### Secure Example

The following example will pass the azure-appservice-enable-http2 check.
```terraform

 resource "azurerm_app_service" "good_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 
   site_config {
 	  http2_enabled = true
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#http2_enabled](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#http2_enabled){:target="_blank" rel="nofollow noreferrer noopener"}




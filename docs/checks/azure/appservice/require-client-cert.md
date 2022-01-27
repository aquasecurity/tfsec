---
title: Web App accepts incoming client certificate
---

# Web App accepts incoming client certificate

### Default Severity: <span class="severity low">low</span>

### Explanation

The TLS mutual authentication technique in enterprise environments ensures the authenticity of clients to the server. If incoming client certificates are enabled only an authenticated client with valid certificates can access the app.

### Possible Impact
Mutual TLS is not being used

### Suggested Resolution
Enable incoming certificates for clients


### Insecure Example

The following example will fail the azure-appservice-require-client-cert check.
```terraform

 resource "azurerm_app_service" "bad_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 }
 
```



### Secure Example

The following example will pass the azure-appservice-require-client-cert check.
```terraform

 resource "azurerm_app_service" "good_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
   client_cert_enabled = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#client_cert_enabled](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#client_cert_enabled){:target="_blank" rel="nofollow noreferrer noopener"}




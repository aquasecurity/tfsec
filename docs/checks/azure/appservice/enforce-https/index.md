---
title: Ensure the Function App can only be accessed via HTTPS. The default is false.
---

# Ensure the Function App can only be accessed via HTTPS. The default is false.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

By default, clients can connect to function endpoints by using both HTTP or HTTPS. You should redirect HTTP to HTTPs because HTTPS uses the SSL/TLS protocol to provide a secure connection, which is both encrypted and authenticated.

### Possible Impact
Anyone can access the Function App using HTTP.

### Suggested Resolution
You can redirect all HTTP requests to the HTTPS port.


### Insecure Example

The following example will fail the azure-appservice-enforce-https check.
```terraform

 resource "azurerm_function_app" "bad_example" {
   name                       = "test-azure-functions"
   location                   = azurerm_resource_group.example.location
   resource_group_name        = azurerm_resource_group.example.name
   app_service_plan_id        = azurerm_app_service_plan.example.id
   storage_account_name       = azurerm_storage_account.example.name
   storage_account_access_key = azurerm_storage_account.example.primary_access_key
   os_type                    = "linux"
 }
 
```



### Secure Example

The following example will pass the azure-appservice-enforce-https check.
```terraform

 resource "azurerm_function_app" "good_example" {
   name                       = "test-azure-functions"
   location                   = azurerm_resource_group.example.location
   resource_group_name        = azurerm_resource_group.example.name
   app_service_plan_id        = azurerm_app_service_plan.example.id
   storage_account_name       = azurerm_storage_account.example.name
   storage_account_access_key = azurerm_storage_account.example.primary_access_key
   os_type                    = "linux"
   https_only                 = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#https_only](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#https_only){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-https](https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-https){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/azure-functions/security-concepts](https://docs.microsoft.com/en-us/azure/azure-functions/security-concepts){:target="_blank" rel="nofollow noreferrer noopener"}




---
title: Storage containers in blob storage mode should not have public access
---

# Storage containers in blob storage mode should not have public access

### Default Severity: <span class="severity high">high</span>

### Explanation

Storage container public access should be off. It can be configured for blobs only, containers and blobs or off entirely. The default is off, with no public access.

Explicitly overriding publicAccess to anything other than off should be avoided.

### Possible Impact
Data in the storage container could be exposed publicly

### Suggested Resolution
Disable public access to storage containers


### Insecure Example

The following example will fail the azure-storage-no-public-access check.
```terraform

 resource "azurerm_storage_container" "bad_example" {
 	name                  = "terraform-container-storage"
 	container_access_type = "blob"
 	
 	properties = {
 		"publicAccess" = "blob"
 	}
 }
 
```



### Secure Example

The following example will pass the azure-storage-no-public-access check.
```terraform

 resource "azurerm_storage_container" "good_example" {
 	name                  = "terraform-container-storage"
 	container_access_type = "private"
 }
 
```



### Links


- [https://www.terraform.io/docs/providers/azure/r/storage_container.html#properties](https://www.terraform.io/docs/providers/azure/r/storage_container.html#properties){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal#set-the-public-access-level-for-a-container](https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal#set-the-public-access-level-for-a-container){:target="_blank" rel="nofollow noreferrer noopener"}




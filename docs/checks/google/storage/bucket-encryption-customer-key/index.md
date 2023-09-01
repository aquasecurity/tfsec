---
title: Cloud Storage buckets should be encrypted with a customer-managed key.
---

# Cloud Storage buckets should be encrypted with a customer-managed key.

### Default Severity: <span class="severity low">low</span>

### Explanation

Using unmanaged keys makes rotation and general management difficult.

### Possible Impact
Using unmanaged keys does not allow for proper key management.

### Suggested Resolution
Encrypt Cloud Storage buckets using customer-managed keys.


### Insecure Example

The following example will fail the google-storage-bucket-encryption-customer-key check.
```terraform

 resource "google_storage_bucket" "default" {
   name                        = "my-default-bucket"
   location                    = "EU"
   force_destroy               = true
   uniform_bucket_level_access = true
 }
 
```



### Secure Example

The following example will pass the google-storage-bucket-encryption-customer-key check.
```terraform

 resource "google_storage_bucket" "default" {
   name                        = "my-default-bucket"
   location                    = "EU"
   force_destroy               = true
   uniform_bucket_level_access = true

   encryption {
     default_kms_key_name = "projects/my-pet-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key"
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#encryption](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#encryption){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/storage/docs/encryption/customer-managed-keys](https://cloud.google.com/storage/docs/encryption/customer-managed-keys){:target="_blank" rel="nofollow noreferrer noopener"}




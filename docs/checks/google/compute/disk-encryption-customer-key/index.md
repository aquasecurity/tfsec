---
title: Disks should be encrypted with customer managed encryption keys
---

# Disks should be encrypted with customer managed encryption keys

### Default Severity: <span class="severity low">low</span>

### Explanation

Using unmanaged keys makes rotation and general management difficult.

### Possible Impact
Using unmanaged keys does not allow for proper key management.

### Suggested Resolution
Use managed keys to encrypt disks.


### Insecure Example

The following example will fail the google-compute-disk-encryption-customer-key check.
```terraform

 resource "google_compute_disk" "bad_example" {
   name  = "test-disk"
   type  = "pd-ssd"
   zone  = "us-central1-a"
   image = "debian-9-stretch-v20200805"
   labels = {
     environment = "dev"
   }
   physical_block_size_bytes = 4096
 }
 
```



### Secure Example

The following example will pass the google-compute-disk-encryption-customer-key check.
```terraform

 resource "google_compute_disk" "good_example" {
   name  = "test-disk"
   type  = "pd-ssd"
   zone  = "us-central1-a"
   image = "debian-9-stretch-v20200805"
   labels = {
     environment = "dev"
   }
   physical_block_size_bytes = 4096
   disk_encryption_key {
     kms_key_self_link = "something"
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#kms_key_self_link](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#kms_key_self_link){:target="_blank" rel="nofollow noreferrer noopener"}




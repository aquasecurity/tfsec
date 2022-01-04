---
title: VM disk encryption keys should not be provided in plaintext
---

### Default Severity: <span class="severity high">high</span>

### Explanation

Providing your encryption key in plaintext format means anyone with access to the source code also has access to the key.

### Possible Impact
Compromise of encryption keys

### Suggested Resolution
Use managed keys or provide the raw key via a secrets manager 


### Insecure Example

The following example will fail the google-compute-no-plaintext-vm-disk-keys check.
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
   disk_encryption_key {
     raw_key = "something"
   }
 }
 
```



### Secure Example

The following example will pass the google-compute-no-plaintext-vm-disk-keys check.
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
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#raw_key](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#raw_key){:target="_blank" rel="nofollow noreferrer noopener"}




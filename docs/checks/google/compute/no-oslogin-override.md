---
title: Instances should not override the project setting for OS Login
---

# Instances should not override the project setting for OS Login

### Default Severity: <span class="severity medium">medium</span>

### Explanation

OS Login automatically revokes the relevant SSH keys when an IAM user has their access revoked.

### Possible Impact
Access via SSH key cannot be revoked automatically when an IAM user is removed.

### Suggested Resolution
Enable OS Login at project level and remove instance-level overrides


### Insecure Example

The following example will fail the google-compute-no-oslogin-override check.
```terraform

 resource "google_compute_instance" "default" {
   name         = "test"
   machine_type = "e2-medium"
   zone         = "us-central1-a"
 
   boot_disk {
     initialize_params {
       image = "debian-cloud/debian-9"
     }
   }
 
   // Local SSD disk
   scratch_disk {
     interface = "SCSI"
   }
 
   metadata = {
     enable-oslogin = false
   }
 }
 
```



### Secure Example

The following example will pass the google-compute-no-oslogin-override check.
```terraform

 resource "google_compute_instance" "default" {
   name         = "test"
   machine_type = "e2-medium"
   zone         = "us-central1-a"
 
   boot_disk {
     initialize_params {
       image = "debian-cloud/debian-9"
     }
   }
 
   // Local SSD disk
   scratch_disk {
     interface = "SCSI"
   }
 
   metadata = {
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#){:target="_blank" rel="nofollow noreferrer noopener"}




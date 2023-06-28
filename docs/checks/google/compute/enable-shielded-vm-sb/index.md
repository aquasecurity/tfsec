---
title: Instances should have Shielded VM secure boot enabled
---

# Instances should have Shielded VM secure boot enabled

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Secure boot helps ensure that the system only runs authentic software.

### Possible Impact
Unable to verify digital signature of boot components, and unable to stop the boot process if verificaiton fails.

### Suggested Resolution
Enable Shielded VM secure boot


### Insecure Example

The following example will fail the google-compute-enable-shielded-vm-sb check.
```terraform

 resource "google_compute_instance" "bad_example" {
   name         = "test"
   machine_type = "e2-medium"
   zone         = "us-central1-a"
 
   tags = ["foo", "bar"]
 
   boot_disk {
     initialize_params {
       image = "debian-cloud/debian-9"
     }
   }
 
   // Local SSD disk
   scratch_disk {
     interface = "SCSI"
   }
 
   shielded_instance_config {
     enable_secure_boot = false
   }
 }
 
```



### Secure Example

The following example will pass the google-compute-enable-shielded-vm-sb check.
```terraform

 resource "google_compute_instance" "good_example" {
   name         = "test"
   machine_type = "e2-medium"
   zone         = "us-central1-a"
 
   tags = ["foo", "bar"]
 
   boot_disk {
     initialize_params {
       image = "debian-cloud/debian-9"
     }
   }
 
   // Local SSD disk
   scratch_disk {
     interface = "SCSI"
   }
 
   shielded_instance_config {
     enable_secure_boot = true
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#enable_secure_boot](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#enable_secure_boot){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/security/shielded-cloud/shielded-vm#secure-boot](https://cloud.google.com/security/shielded-cloud/shielded-vm#secure-boot){:target="_blank" rel="nofollow noreferrer noopener"}




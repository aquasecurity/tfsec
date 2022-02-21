---
title: Instances should have Shielded VM VTPM enabled
---

# Instances should have Shielded VM VTPM enabled

### Default Severity: <span class="severity medium">medium</span>

### Explanation

The virtual TPM provides numerous security measures to your VM.

### Possible Impact
Unable to prevent unwanted system state modification

### Suggested Resolution
Enable Shielded VM VTPM


### Insecure Example

The following example will fail the google-compute-enable-shielded-vm-vtpm check.
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
     enable_vtpm = false
   }
 }
 
```



### Secure Example

The following example will pass the google-compute-enable-shielded-vm-vtpm check.
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
     enable_vtpm = true
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#enable_vtpm](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#enable_vtpm){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/blog/products/identity-security/virtual-trusted-platform-module-for-shielded-vms-security-in-plaintext](https://cloud.google.com/blog/products/identity-security/virtual-trusted-platform-module-for-shielded-vms-security-in-plaintext){:target="_blank" rel="nofollow noreferrer noopener"}




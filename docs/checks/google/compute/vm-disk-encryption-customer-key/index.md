---
title: VM disks should be encrypted with Customer Supplied Encryption Keys
---

# VM disks should be encrypted with Customer Supplied Encryption Keys

### Default Severity: <span class="severity low">low</span>

### Explanation

Using unmanaged keys makes rotation and general management difficult.

### Possible Impact
Using unmanaged keys does not allow for proper management

### Suggested Resolution
Use managed keys 


### Insecure Example

The following example will fail the google-compute-vm-disk-encryption-customer-key check.
```terraform

 resource "google_service_account" "default" {
   account_id   = "service_account_id"
   display_name = "Service Account"
 }
 
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
 
   network_interface {
     network = "default"
 
     access_config {
       // Ephemeral IP
     }
   }
 
   metadata = {
     foo = "bar"
   }
 
   metadata_startup_script = "echo hi > /test.txt"
 
   service_account {
     # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
     email  = google_service_account.default.email
     scopes = ["cloud-platform"]
   }
 }
 
```



### Secure Example

The following example will pass the google-compute-vm-disk-encryption-customer-key check.
```terraform

 resource "google_service_account" "default" {
   account_id   = "service_account_id"
   display_name = "Service Account"
 }
 
 resource "google_compute_instance" "good_example" {
   name         = "test"
   machine_type = "e2-medium"
   zone         = "us-central1-a"
 
   tags = ["foo", "bar"]
 
   boot_disk {
     initialize_params {
       image = "debian-cloud/debian-9"
     }
     kms_key_self_link = "something"
   }
 
   // Local SSD disk
   scratch_disk {
     interface = "SCSI"
   }
 
   network_interface {
     network = "default"
 
     access_config {
       // Ephemeral IP
     }
   }
 
   metadata = {
     foo = "bar"
   }
 
   metadata_startup_script = "echo hi > /test.txt"
 
   service_account {
     # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
     email  = google_service_account.default.email
     scopes = ["cloud-platform"]
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#kms_key_self_link](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#kms_key_self_link){:target="_blank" rel="nofollow noreferrer noopener"}




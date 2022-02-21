---
title: Instances should not use the default service account
---

# Instances should not use the default service account

### Default Severity: <span class="severity critical">critical</span>

### Explanation

The default service account has full project access. Instances should instead be assigned the minimal access they need.

### Possible Impact
Instance has full access to the project

### Suggested Resolution
Remove use of default service account


### Insecure Example

The following example will fail the google-compute-no-default-service-account check.
```terraform

 resource "google_compute_instance" "default" {
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
 
   service_account {
     # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
     email  = "1234567890-compute@developer.gserviceaccount.com"
     scopes = ["cloud-platform"]
   }
 }
 
```



### Secure Example

The following example will pass the google-compute-no-default-service-account check.
```terraform

 resource "google_service_account" "default" {
   account_id   = "service_account_id"
   display_name = "Service Account"
 }
 
 resource "google_compute_instance" "default" {
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



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#){:target="_blank" rel="nofollow noreferrer noopener"}




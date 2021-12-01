---
title: no-plaintext-vm-disk-keys
---

### Explanation

Providing your encryption key in plaintext format means anyone with access to the source code also has access to the key.

### Possible Impact
Compromise of encryption keys

### Suggested Resolution
Use managed keys or provide the raw key via a secrets manager 


### Insecure Example

The following example will fail the google-compute-no-plaintext-vm-disk-keys check.

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
    disk_encryption_key_raw = "something"
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

The following example will pass the google-compute-no-plaintext-vm-disk-keys check.

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




### Related Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#disk_encryption_key_raw](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#disk_encryption_key_raw){:target="_blank" rel="nofollow noreferrer noopener"}



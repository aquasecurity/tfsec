---
title: no-public-ip
---

### Explanation

Instances should not be publicly exposed to the internet

### Possible Impact
Direct exposure of an instance to the public internet

### Suggested Resolution
Remove public IP


### Insecure Example

The following example will fail the google-compute-no-public-ip check.

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

  network_interface {
    network = "default"

    access_config {
      // Ephemeral IP
    }
  }
}

```



### Secure Example

The following example will pass the google-compute-no-public-ip check.

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

  network_interface {
    network = "default"
  }
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#access_config](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#access_config){:target="_blank" rel="nofollow noreferrer noopener"}



---
title: VPC flow logs should be enabled for all subnetworks
---

# VPC flow logs should be enabled for all subnetworks

### Default Severity: <span class="severity low">low</span>

### Explanation

VPC flow logs record information about all traffic, which is a vital tool in reviewing anomalous traffic.

### Possible Impact
Limited auditing capability and awareness

### Suggested Resolution
Enable VPC flow logs


### Insecure Example

The following example will fail the google-compute-enable-vpc-flow-logs check.
```terraform

resource "google_compute_subnetwork" "bad_example" {
  name          = "test-subnetwork"
  ip_cidr_range = "10.2.0.0/16"
  region        = "us-central1"
  network       = google_compute_network.custom-test.id
  secondary_ip_range {
    range_name    = "tf-test-secondary-range-update1"
    ip_cidr_range = "192.168.10.0/24"
  }
}
resource "google_compute_network" "custom-test" {
  name                    = "test-network"
  auto_create_subnetworks = false
}

```



### Secure Example

The following example will pass the google-compute-enable-vpc-flow-logs check.
```terraform

resource "google_compute_subnetwork" "good_example" {
  name          = "test-subnetwork"
  ip_cidr_range = "10.2.0.0/16"
  region        = "us-central1"
  network       = google_compute_network.custom-test.id
  secondary_ip_range {
    range_name    = "tf-test-secondary-range-update1"
    ip_cidr_range = "192.168.10.0/24"
  }
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}
resource "google_compute_network" "custom-test" {
  name                    = "test-network"
  auto_create_subnetworks = false
}

```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_subnetwork#enable_flow_logs](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_subnetwork#enable_flow_logs){:target="_blank" rel="nofollow noreferrer noopener"}




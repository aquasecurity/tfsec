---
title: An outbound firewall rule allows traffic to /0.
---

# An outbound firewall rule allows traffic to /0.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets and avoid using the <code>/0</code> subnet.

### Possible Impact
The port is exposed for egress to the internet

### Suggested Resolution
Set a more restrictive cidr range


### Insecure Example

The following example will fail the google-compute-no-public-egress check.
```terraform

resource "google_compute_firewall" "bad_example" {
  direction = "EGRESS"
  allow {
    protocol = "icmp"
  }
  destination_ranges = ["0.0.0.0/0"]
}
```



### Secure Example

The following example will pass the google-compute-no-public-egress check.
```terraform

 resource "google_compute_firewall" "good_example" {
  direction = "EGRESS"
  allow {
    protocol = "icmp"
  }
  destination_ranges = ["1.2.3.4/32"]
}
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/vpc/docs/using-firewalls](https://cloud.google.com/vpc/docs/using-firewalls){:target="_blank" rel="nofollow noreferrer noopener"}




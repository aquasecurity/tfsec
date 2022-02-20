---
title: An inbound firewall rule allows traffic from /0.
---

# An inbound firewall rule allows traffic from /0.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets and avoid using the <code>/0</code> subnet.

### Possible Impact
The port is exposed for ingress from the internet

### Suggested Resolution
Set a more restrictive cidr range


### Insecure Example

The following example will fail the google-compute-no-public-ingress check.
```terraform

resource "google_compute_firewall" "bad_example" {
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "icmp"
  }
}
```



### Secure Example

The following example will pass the google-compute-no-public-ingress check.
```terraform

resource "google_compute_firewall" "good_example" {
  source_ranges = ["1.2.3.4/32"]
  allow {
    protocol = "icmp"
  }
}
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#source_ranges](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#source_ranges){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://www.terraform.io/docs/providers/google/r/compute_firewall.html](https://www.terraform.io/docs/providers/google/r/compute_firewall.html){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/vpc/docs/using-firewalls](https://cloud.google.com/vpc/docs/using-firewalls){:target="_blank" rel="nofollow noreferrer noopener"}




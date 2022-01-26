---
title: Cloud DNS should use DNSSEC
---

# Cloud DNS should use DNSSEC

### Default Severity: <span class="severity medium">medium</span>

### Explanation

DNSSEC authenticates DNS responses, preventing MITM attacks and impersonation.

### Possible Impact
Unverified DNS responses could lead to man-in-the-middle attacks

### Suggested Resolution
Enable DNSSEC


### Insecure Example

The following example will fail the google-dns-enable-dnssec check.
```terraform

 resource "google_dns_managed_zone" "bad_example" {
   name        = "example-zone"
   dns_name    = "example-${random_id.rnd.hex}.com."
   description = "Example DNS zone"
   labels = {
     foo = "bar"
   }
   dnssec_config {
     state = "off"
   }
 }
 
 resource "random_id" "rnd" {
   byte_length = 4
 }
 
```



### Secure Example

The following example will pass the google-dns-enable-dnssec check.
```terraform

 resource "google_dns_managed_zone" "good_example" {
   name        = "example-zone"
   dns_name    = "example-${random_id.rnd.hex}.com."
   description = "Example DNS zone"
   labels = {
     foo = "bar"
   }
   dnssec_config {
     state = "on"
   }
 }
 
 resource "random_id" "rnd" {
   byte_length = 4
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/dns_managed_zone#state](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/dns_managed_zone#state){:target="_blank" rel="nofollow noreferrer noopener"}




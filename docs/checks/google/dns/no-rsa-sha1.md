---
title: Zone signing should not use RSA SHA1
---

# Zone signing should not use RSA SHA1

### Default Severity: <span class="severity medium">medium</span>

### Explanation

RSA SHA1 is a weaker algorithm than SHA2-based algorithms such as RSA SHA256/512

### Possible Impact
Less secure encryption algorithm than others available

### Suggested Resolution
Use RSA SHA512


### Insecure Example

The following example will fail the google-dns-no-rsa-sha1 check.
```terraform

 resource "google_dns_managed_zone" "foo" {
 	name     = "foobar"
 	dns_name = "foo.bar."
 	
 	dnssec_config {
 		state         = "on"
 		non_existence = "nsec3"
 	}
 }
 	
 data "google_dns_keys" "foo_dns_keys" {
 	managed_zone = google_dns_managed_zone.foo.id
 	zone_signing_keys {
 		algorithm = "rsasha1"
 	}
 }
 	
 output "foo_dns_ds_record" {
 	description = "DS record of the foo subdomain."
 	value       = data.google_dns_keys.foo_dns_keys.key_signing_keys[0].ds_record
 }
 
```



### Secure Example

The following example will pass the google-dns-no-rsa-sha1 check.
```terraform

 resource "google_dns_managed_zone" "foo" {
 	name     = "foobar"
 	dns_name = "foo.bar."
 	
 	dnssec_config {
 		state         = "on"
 		non_existence = "nsec3"
 	}
 }
 	
 data "google_dns_keys" "foo_dns_keys" {
 	managed_zone = google_dns_managed_zone.foo.id
 	zone_signing_keys {
 		algorithm = "rsasha512"
 	}
 }
 	
 output "foo_dns_ds_record" {
 	description = "DS record of the foo subdomain."
 	value       = data.google_dns_keys.foo_dns_keys.key_signing_keys[0].ds_record
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/dns_managed_zone#algorithm](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/dns_managed_zone#algorithm){:target="_blank" rel="nofollow noreferrer noopener"}




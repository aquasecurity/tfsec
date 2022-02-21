---
title: Compute instance requests an IP reservation from a public pool
---

# Compute instance requests an IP reservation from a public pool

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Compute instance requests an IP reservation from a public pool

The compute instance has the ability to be reached from outside, you might want to sonder the use of a non public IP.

### Possible Impact
The compute instance has the ability to be reached from outside

### Suggested Resolution
Reconsider the use of an public IP


### Insecure Example

The following example will fail the oracle-compute-no-public-ip check.
```terraform

 resource "opc_compute_ip_address_reservation" "bad_example" {
 	name            = "my-ip-address"
 	ip_address_pool = "public-ippool"
   }
 
```



### Secure Example

The following example will pass the oracle-compute-no-public-ip check.
```terraform

 resource "opc_compute_ip_address_reservation" "good_example" {
 	name            = "my-ip-address"
 	ip_address_pool = "cloud-ippool"
   }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/opc/latest/docs/resources/opc_compute_ip_address_reservation](https://registry.terraform.io/providers/hashicorp/opc/latest/docs/resources/opc_compute_ip_address_reservation){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/opc/latest/docs/resources/opc_compute_instance](https://registry.terraform.io/providers/hashicorp/opc/latest/docs/resources/opc_compute_instance){:target="_blank" rel="nofollow noreferrer noopener"}




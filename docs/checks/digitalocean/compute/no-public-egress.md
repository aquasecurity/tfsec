---
title: The firewall has an outbound rule with open access
---

# The firewall has an outbound rule with open access

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.

### Possible Impact
The port is exposed for ingress from the internet

### Suggested Resolution
Set a more restrictive cidr range


### Insecure Example

The following example will fail the digitalocean-compute-no-public-egress check.
```terraform

 resource "digitalocean_firewall" "bad_example" {
 	name = "only-22-80-and-443"
   
 	droplet_ids = [digitalocean_droplet.web.id]
   
 	outbound_rule {
 	  protocol         = "tcp"
 	  port_range       = "22"
 	  destination_addresses = ["0.0.0.0/0", "::/0"]
 	}
 }
 
```



### Secure Example

The following example will pass the digitalocean-compute-no-public-egress check.
```terraform

 resource "digitalocean_firewall" "good_example" {
 	name = "only-22-80-and-443"
   
 	droplet_ids = [digitalocean_droplet.web.id]
   
 	outbound_rule {
 	  protocol         = "tcp"
 	  port_range       = "22"
 	  destination_addresses = ["192.168.1.0/24", "fc00::/7"]
 	}
 }
 
```



### Links


- [https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/firewall](https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/firewall){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/](https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/){:target="_blank" rel="nofollow noreferrer noopener"}




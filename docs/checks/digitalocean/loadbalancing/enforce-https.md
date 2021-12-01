---
title: enforce-https
---

### Explanation


Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.


### Possible Impact
Your inbound traffic is not protected

### Suggested Resolution
Switch to HTTPS to benefit from TLS security features


### Insecure Example

The following example will fail the digitalocean-loadbalancing-enforce-https check.

```terraform

resource "digitalocean_loadbalancer" "bad_example" {
  name   = "bad_example-1"
  region = "nyc3"

  forwarding_rule {
    entry_port     = 80
    entry_protocol = "http"

    target_port     = 80
    target_protocol = "http"
  }

  droplet_ids = [digitalocean_droplet.web.id]
}

```



### Secure Example

The following example will pass the digitalocean-loadbalancing-enforce-https check.

```terraform

resource "digitalocean_loadbalancer" "bad_example" {
  name   = "bad_example-1"
  region = "nyc3"
  
  forwarding_rule {
	entry_port     = 443
	entry_protocol = "https"
  
	target_port     = 443
	target_protocol = "https"
  }
  
  droplet_ids = [digitalocean_droplet.web.id]
}

```




### Related Links


- [https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/loadbalancer](https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/loadbalancer){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.digitalocean.com/products/networking/load-balancers/](https://docs.digitalocean.com/products/networking/load-balancers/){:target="_blank" rel="nofollow noreferrer noopener"}



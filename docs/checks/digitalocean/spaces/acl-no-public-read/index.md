---
title: Spaces bucket or bucket object has public read acl set
---

# Spaces bucket or bucket object has public read acl set

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Space bucket and bucket object permissions should be set to deny public access unless explicitly required.

### Possible Impact
The contents of the space can be accessed publicly

### Suggested Resolution
Apply a more restrictive ACL


### Insecure Example

The following example will fail the digitalocean-spaces-acl-no-public-read check.
```terraform

 resource "digitalocean_spaces_bucket" "bad_example" {
   name   = "public_space"
   region = "nyc3"
   acl    = "public-read"
 }
 
 resource "digitalocean_spaces_bucket_object" "index" {
   region       = digitalocean_spaces_bucket.bad_example.region
   bucket       = digitalocean_spaces_bucket.bad_example.name
   key          = "index.html"
   content      = "<html><body><p>This page is empty.</p></body></html>"
   content_type = "text/html"
   acl          = "public-read"
 }
 
```



### Secure Example

The following example will pass the digitalocean-spaces-acl-no-public-read check.
```terraform

 resource "digitalocean_spaces_bucket" "good_example" {
   name   = "private_space"
   region = "nyc3"
   acl    = "private"
 }
   
 resource "digitalocean_spaces_bucket_object" "index" {
   region       = digitalocean_spaces_bucket.good_example.region
   bucket       = digitalocean_spaces_bucket.good_example.name
   key          = "index.html"
   content      = "<html><body><p>This page is empty.</p></body></html>"
   content_type = "text/html"
 }
 
```



### Links


- [https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket#acl](https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket#acl){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket_object#acl](https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket_object#acl){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.digitalocean.com/reference/api/spaces-api/#access-control-lists-acls](https://docs.digitalocean.com/reference/api/spaces-api/#access-control-lists-acls){:target="_blank" rel="nofollow noreferrer noopener"}




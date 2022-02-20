---
title: Spaces buckets should have versioning enabled
---

# Spaces buckets should have versioning enabled

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Versioning is a means of keeping multiple variants of an object in the same bucket. You can use the Spaces (S3) Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets. With versioning you can recover more easily from both unintended user actions and application failures.

### Possible Impact
Deleted or modified data would not be recoverable

### Suggested Resolution
Enable versioning to protect against accidental or malicious removal or modification


### Insecure Example

The following example will fail the digitalocean-spaces-versioning-enabled check.
```terraform

 resource "digitalocean_spaces_bucket" "bad_example" {
   name   = "foobar"
   region = "nyc3"
 }
 
 resource "digitalocean_spaces_bucket" "bad_example" {
   name   = "foobar"
   region = "nyc3"
 
   versioning {
 	enabled = false	
   }
 }
 
```



### Secure Example

The following example will pass the digitalocean-spaces-versioning-enabled check.
```terraform

 resource "digitalocean_spaces_bucket" "good_example" {
   name   = "foobar"
   region = "nyc3"
 
   versioning {
 	enabled = true
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket#versioning](https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket#versioning){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html){:target="_blank" rel="nofollow noreferrer noopener"}




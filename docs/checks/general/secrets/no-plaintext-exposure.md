---
title: Secret/sensitive data should not be exposed in plaintext.
---

# Secret/sensitive data should not be exposed in plaintext.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Plaintext secrets kept in source code or similar media mean sensitive data is exposed to any users/systems with access to the source code.

### Possible Impact
Sensitive data can be leaked to unauthorised people or systems.

### Suggested Resolution
Remove plaintext secrets and encrypt them within a secrets manager instead.


### Insecure Example

The following example will fail the general-secrets-no-plaintext-exposure check.
```terraform

 variable "password" {
   description = "The root password for our VM"
   type        = string
   default     = "p4ssw0rd"
 }
 
 resource "evil_corp" "virtual_machine" {
 	root_password = var.password
 }
 
```



### Secure Example

The following example will pass the general-secrets-no-plaintext-exposure check.
```terraform

 variable "password" {
   description = "The root password for our VM"
   type        = string
 }
 
 resource "evil_corp" "virtual_machine" {
 	root_password = var.password
 }
 
```



### Links


- [https://www.terraform.io/docs/state/sensitive-data.html](https://www.terraform.io/docs/state/sensitive-data.html){:target="_blank" rel="nofollow noreferrer noopener"}




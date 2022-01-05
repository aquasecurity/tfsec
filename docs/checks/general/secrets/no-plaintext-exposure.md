---
title: Secret/sensitive data should not be exposed in plaintext.
---

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

 provider "aws" {
   access_key = "AKIAABCD12ABCDEF1ABC"
   secret_key = "s8d7ghas9dghd9ophgs9"
 }
 
```



### Secure Example

The following example will pass the general-secrets-no-plaintext-exposure check.
```terraform

 provider "aws" {
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs#argument-reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#argument-reference){:target="_blank" rel="nofollow noreferrer noopener"}




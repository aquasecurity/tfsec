---
title: sensitive-in-local
---

### Explanation


Sensitive attributes such as passwords and API tokens should not be available in your templates, especially in a plaintext form. You can declare variables to hold the secrets, assuming you can provide values for those variables in a secure fashion. Alternatively, you can store these secrets in a secure secret store, such as AWS KMS.

*NOTE: It is also recommended to store your Terraform state in an encrypted form.*


### Possible Impact
Local value could be leaking secrets

### Suggested Resolution
Don't include sensitive data in locals


### Insecure Example

The following example will fail the general-secrets-sensitive-in-local check.

```terraform

locals {
  password = "p4ssw0rd"
}

resource "evil_corp" "bad_example" {
	root_password = local.password
}

```



### Secure Example

The following example will pass the general-secrets-sensitive-in-local check.

```terraform

variable "password" {
  description = "The root password for our VM"
  type        = string
}

resource "evil_corp" "good_example" {
	root_password = var.password
}

```




### Related Links


- [https://www.terraform.io/docs/state/sensitive-data.html](https://www.terraform.io/docs/state/sensitive-data.html){:target="_blank" rel="nofollow noreferrer noopener"}



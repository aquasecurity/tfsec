---
title: sensitive-in-attribute-value
---

### Explanation


Sensitive data stored in attributes can result in compromised data. Sensitive data should be passed in through secret variables



### Possible Impact
Sensitive credentials may be compromised

### Suggested Resolution
Check the code for vulnerabilities and move to variables


### Insecure Example

The following example will fail the general-secrets-sensitive-in-attribute-value check.

```terraform

resource "aws_instance" "bad_example" {
	instance_type = "t2.small"

	user_data = <<EOF
		Password = "something secret"
EOF

}

```



### Secure Example

The following example will pass the general-secrets-sensitive-in-attribute-value check.

```terraform

variable "password" {
	type = string
}

resource "aws_instance" "good_instance" {
	instance_type = "t2.small"

	user_data = <<EOF
		export EDITOR=vimacs
EOF

}

```




### Related Links


- [https://www.terraform.io/docs/state/sensitive-data.html](https://www.terraform.io/docs/state/sensitive-data.html){:target="_blank" rel="nofollow noreferrer noopener"}



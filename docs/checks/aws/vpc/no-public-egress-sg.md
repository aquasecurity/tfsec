---
title: no-public-egress-sg
---

### Explanation


Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.


### Possible Impact
The port is exposed for egressing data to the internet

### Suggested Resolution
Set a more restrictive cidr range


### Insecure Example

The following example will fail the aws-vpc-no-public-egress-sg check.

```terraform

resource "aws_security_group" "bad_example" {
	egress {
		cidr_blocks = ["0.0.0.0/0"]
	}
}

```



### Secure Example

The following example will pass the aws-vpc-no-public-egress-sg check.

```terraform

resource "aws_security_group" "good_example" {
	egress {
		cidr_blocks = ["1.2.3.4/32"]
	}
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group){:target="_blank" rel="nofollow noreferrer noopener"}



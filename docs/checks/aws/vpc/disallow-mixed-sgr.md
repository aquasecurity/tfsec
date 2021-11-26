---
title: disallow-mixed-sgr
---

### Explanation


Mixing Terraform standalone security_group_rule resource and security_group resource with inline ingress/egress rules results in rules being overwritten during Terraform apply.


### Possible Impact
Security group rules will be overwritten and will result in unintended blocking of network traffic

### Suggested Resolution
Either define all of a security group's rules inline, or none of the security group's rules inline


### Insecure Example

The following example will fail the aws-vpc-disallow-mixed-sgr check.

```terraform

resource "aws_security_group_rule" "bad_example" {
  	security_group_id = aws_security_group.bad_example_sg.id
	type = "ingress"
	cidr_blocks = ["172.31.0.0/16"]
}

resource "aws_security_group" "bad_example_sg" {
	ingress {
		cidr_blocks = ["10.0.0.0/16"]
	}
}

```



### Secure Example

The following example will pass the aws-vpc-disallow-mixed-sgr check.

```terraform

resource "aws_security_group_rule" "good_example" {
  	security_group_id = aws_security_group.good_example_sg.id
	type = "ingress"
	cidr_blocks = ["10.0.0.0/16", "172.31.0.0/16"]
}

resource "aws_security_group" "good_example_sg" {
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group#resource-aws_security_group](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group#resource-aws_security_group){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://github.com/hashicorp/terraform/issues/11011#issuecomment-283076580](https://github.com/hashicorp/terraform/issues/11011#issuecomment-283076580){:target="_blank" rel="nofollow noreferrer noopener"}



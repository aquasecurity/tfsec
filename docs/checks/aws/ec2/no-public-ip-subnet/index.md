---
title: Instances in a subnet should not receive a public IP address by default.
---

# Instances in a subnet should not receive a public IP address by default.

### Default Severity: <span class="severity high">high</span>

### Explanation

You should limit the provision of public IP addresses for resources. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application.

### Possible Impact
The instance is publicly accessible

### Suggested Resolution
Set the instance to not be publicly accessible


### Insecure Example

The following example will fail the aws-ec2-no-public-ip-subnet check.
```terraform

 resource "aws_subnet" "bad_example" {
	vpc_id                  = "vpc-123456"
	map_public_ip_on_launch = true
 }
 
```



### Secure Example

The following example will pass the aws-ec2-no-public-ip-subnet check.
```terraform

 resource "aws_subnet" "good_example" {
	vpc_id                  = "vpc-123456"
	map_public_ip_on_launch = false
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet#map_public_ip_on_launch](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet#map_public_ip_on_launch){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html#concepts-public-addresses](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html#concepts-public-addresses){:target="_blank" rel="nofollow noreferrer noopener"}




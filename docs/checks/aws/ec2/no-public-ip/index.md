---
title: Launch configuration should not have a public IP address.
---

# Launch configuration should not have a public IP address.

### Default Severity: <span class="severity high">high</span>

### Explanation

You should limit the provision of public IP addresses for resources. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application.

### Possible Impact
The instance or configuration is publicly accessible

### Suggested Resolution
Set the instance to not be publicly accessible


### Insecure Example

The following example will fail the aws-ec2-no-public-ip check.
```terraform

 resource "aws_launch_configuration" "bad_example" {
 	associate_public_ip_address = true
 }
 
```



### Secure Example

The following example will pass the aws-ec2-no-public-ip check.
```terraform

 resource "aws_launch_configuration" "good_example" {
 	associate_public_ip_address = false
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration#associate_public_ip_address](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration#associate_public_ip_address){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#associate_public_ip_address](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#associate_public_ip_address){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html){:target="_blank" rel="nofollow noreferrer noopener"}




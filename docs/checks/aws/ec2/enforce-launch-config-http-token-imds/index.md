---
title: aws_instance should activate session tokens for Instance Metadata Service.
---

# aws_instance should activate session tokens for Instance Metadata Service.

### Default Severity: <span class="severity high">high</span>

### Explanation


IMDS v2 (Instance Metadata Service) introduced session authentication tokens which improve security when talking to IMDS.
By default <code>aws_instance</code> resource sets IMDS session auth tokens to be optional. 
To fully protect IMDS you need to enable session tokens by using <code>metadata_options</code> block and its <code>http_tokens</code> variable set to <code>required</code>.


### Possible Impact
Instance metadata service can be interacted with freely

### Suggested Resolution
Enable HTTP token requirement for IMDS


### Insecure Example

The following example will fail the aws-ec2-enforce-launch-config-http-token-imds check.
```terraform

 resource "aws_launch_template" "bad_example" {
	 image_id      = "ami-005e54dee72cc1d00"
	 instance_type = "t2.micro"
 }
 
```



### Secure Example

The following example will pass the aws-ec2-enforce-launch-config-http-token-imds check.
```terraform

 resource "aws_launch_template" "good_example" {
	 image_id      = "ami-005e54dee72cc1d00"
	 instance_type = "t2.micro"
	 metadata_options {
	   http_tokens = "required"
	 }	
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#metadata-options](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#metadata-options){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service){:target="_blank" rel="nofollow noreferrer noopener"}




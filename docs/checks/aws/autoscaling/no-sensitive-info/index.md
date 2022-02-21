---
title: Ensure all data stored in the launch configuration EBS is securely encrypted
---

# Ensure all data stored in the launch configuration EBS is securely encrypted

### Default Severity: <span class="severity high">high</span>

### Explanation

When creating Launch Configurations, user data can be used for the initial configuration of the instance. User data must not contain any sensitive data.

### Possible Impact
Sensitive credentials in user data can be leaked

### Suggested Resolution
Don't use sensitive data in user data


### Insecure Example

The following example will fail the aws-autoscaling-no-sensitive-info check.
```terraform

 resource "aws_launch_configuration" "as_conf" {
   name          = "web_config"
   image_id      = data.aws_ami.ubuntu.id
   instance_type = "t2.micro"
   user_data     = <<EOF
 export DATABASE_PASSWORD=\"SomeSortOfPassword\"
 EOF
 }
 
```



### Secure Example

The following example will pass the aws-autoscaling-no-sensitive-info check.
```terraform

 resource "aws_launch_configuration" "as_conf" {
   name          = "web_config"
   image_id      = data.aws_ami.ubuntu.id
   instance_type = "t2.micro"
   user_data     = <<EOF
 export GREETING="Hello there"
 EOF
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration#user_data,user_data_base64](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration#user_data,user_data_base64){:target="_blank" rel="nofollow noreferrer noopener"}




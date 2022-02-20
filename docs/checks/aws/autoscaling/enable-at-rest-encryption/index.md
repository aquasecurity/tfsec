---
title: Launch configuration with unencrypted block device.
---

# Launch configuration with unencrypted block device.

### Default Severity: <span class="severity high">high</span>

### Explanation

Block devices should be encrypted to ensure sensitive data is held securely at rest.

### Possible Impact
The block device could be compromised and read from

### Suggested Resolution
Turn on encryption for all block devices


### Insecure Example

The following example will fail the aws-autoscaling-enable-at-rest-encryption check.
```terraform

 resource "aws_launch_configuration" "bad_example" {
 	root_block_device {
 		encrypted = false
 	}
 }
 
```



### Secure Example

The following example will pass the aws-autoscaling-enable-at-rest-encryption check.
```terraform

 resource "aws_launch_configuration" "good_example" {
 	root_block_device {
 		encrypted = true
 	}
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs-ephemeral-and-root-block-devices](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs-ephemeral-and-root-block-devices){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html){:target="_blank" rel="nofollow noreferrer noopener"}




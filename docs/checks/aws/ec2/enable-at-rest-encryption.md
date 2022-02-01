---
title: Instance with unencrypted block device.
---

# Instance with unencrypted block device.

### Default Severity: <span class="severity high">high</span>

### Explanation

Block devices should be encrypted to ensure sensitive data is held securely at rest.

### Possible Impact
The block device could be compromised and read from

### Suggested Resolution
Turn on encryption for all block devices


### Insecure Example

The following example will fail the aws-ec2-enable-at-rest-encryption check.
```terraform

resource "aws_instance" "bad_example" {
  ami = "ami-7f89a64f"
  instance_type = "t1.micro"

  root_block_device {
      encrypted = false
  }

  ebs_block_device {
    device_name = "/dev/sdg"
    volume_size = 5
    volume_type = "gp2"
    delete_on_termination = false
    encrypted = false
  }
}
 
```



### Secure Example

The following example will pass the aws-ec2-enable-at-rest-encryption check.
```terraform

resource "aws_instance" "good_example" {
  ami = "ami-7f89a64f"
  instance_type = "t1.micro"

  root_block_device {
      encrypted = true
  }

  ebs_block_device {
    device_name = "/dev/sdg"
    volume_size = 5
    volume_type = "gp2"
    delete_on_termination = false
    encrypted = true
  }
}
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs-ephemeral-and-root-block-devices](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs-ephemeral-and-root-block-devices){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html){:target="_blank" rel="nofollow noreferrer noopener"}




---
title: Enable local-disk encryption for EMR clusters.
---

# Enable local-disk encryption for EMR clusters.

### Default Severity: <span class="severity high">high</span>

### Explanation

Data stored within an EMR instances should be encrypted to ensure sensitive data is kept private.

### Possible Impact
Local-disk data in the EMR cluster could be compromised if accessed.

### Suggested Resolution
Enable local-disk encryption for EMR cluster


### Insecure Example

The following example will fail the aws-emr-enable-local-disk-encryption check.
```terraform

  resource "aws_emr_security_configuration" "bad_example" {
    name = "emrsc_other"
    
    configuration = <<EOF
  {
    "EncryptionConfiguration": {
      "AtRestEncryptionConfiguration": {
        "S3EncryptionConfiguration": {
          "EncryptionMode": "SSE-S3"
        },
        "LocalDiskEncryptionConfiguration": {
          "EncryptionKeyProviderType": "",
          "AwsKmsKey": ""
        }
      },
      "EnableInTransitEncryption": false,
      "EnableAtRestEncryption": false
    }
  }
  EOF
  }
```



### Secure Example

The following example will pass the aws-emr-enable-local-disk-encryption check.
```terraform

  resource "aws_emr_security_configuration" "good_example" {
    name = "emrsc_other"
  
    configuration = <<EOF
  {
    "EncryptionConfiguration": {
      "AtRestEncryptionConfiguration": {
        "S3EncryptionConfiguration": {
          "EncryptionMode": "SSE-S3"
        },
        "LocalDiskEncryptionConfiguration": {
          "EncryptionKeyProviderType": "AwsKms",
          "AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
        }
      },
      "EnableInTransitEncryption": true,
      "EnableAtRestEncryption": true
    }
  }
  EOF
  }
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/emr_security_configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/emr_security_configuration){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist_800-171.html](https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist_800-171.html){:target="_blank" rel="nofollow noreferrer noopener"}




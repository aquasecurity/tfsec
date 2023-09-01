---
title: A MSK cluster allows unencrypted data at rest.
---

# A MSK cluster allows unencrypted data at rest.

### Default Severity: <span class="severity high">high</span>

### Explanation

Encryption should be forced for Kafka clusters, including at rest. This ensures sensitive data is kept private.

### Possible Impact
Intercepted data can be read at rest

### Suggested Resolution
Enable at rest encryption


### Insecure Example

The following example will fail the aws-msk-enable-at-rest-encryption check.
```terraform

 resource "aws_msk_cluster" "bad_example" {
 	encryption_info {
 	}
 }
 
```



### Secure Example

The following example will pass the aws-msk-enable-at-rest-encryption check.
```terraform

 resource "aws_msk_cluster" "good_example" {
 	encryption_info {
		encryption_at_rest_kms_key_arn = "foo-bar-key"
 	}
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#encryption_info-argument-reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#encryption_info-argument-reference){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html](https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html){:target="_blank" rel="nofollow noreferrer noopener"}




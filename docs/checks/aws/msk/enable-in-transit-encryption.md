---
title: A MSK cluster allows unencrypted data in transit.
---

# A MSK cluster allows unencrypted data in transit.

### Default Severity: <span class="severity high">high</span>

### Explanation

Encryption should be forced for Kafka clusters, including for communication between nodes. This ensure sensitive data is kept private.

### Possible Impact
Intercepted data can be read in transit

### Suggested Resolution
Enable in transit encryption


### Insecure Example

The following example will fail the aws-msk-enable-in-transit-encryption check.
```terraform

 resource "aws_msk_cluster" "bad_example" {
 	encryption_info {
 		encryption_in_transit {
 			client_broker = "TLS_PLAINTEXT"
 			in_cluster = true
 		}
 	}
 }
 
```



### Secure Example

The following example will pass the aws-msk-enable-in-transit-encryption check.
```terraform

 resource "aws_msk_cluster" "good_example" {
 	encryption_info {
 		encryption_in_transit {
 			client_broker = "TLS"
 			in_cluster = true
 		}
 	}
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#encryption_info-argument-reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#encryption_info-argument-reference){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html](https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html){:target="_blank" rel="nofollow noreferrer noopener"}




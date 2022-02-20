---
title: DynamoDB tables should use at rest encryption with a Customer Managed Key
---

# DynamoDB tables should use at rest encryption with a Customer Managed Key

### Default Severity: <span class="severity low">low</span>

### Explanation

DynamoDB tables are encrypted by default using AWS managed encryption keys. To increase control of the encryption and control the management of factors like key rotation, use a Customer Managed Key.

### Possible Impact
Using AWS managed keys does not allow for fine grained control

### Suggested Resolution
Enable server side encryption with a customer managed key


### Insecure Example

The following example will fail the aws-dynamodb-table-customer-key check.
```terraform

 resource "aws_dynamodb_table" "bad_example" {
 	name             = "example"
 	hash_key         = "TestTableHashKey"
 	billing_mode     = "PAY_PER_REQUEST"
 	stream_enabled   = true
 	stream_view_type = "NEW_AND_OLD_IMAGES"
   
 	attribute {
 	  name = "TestTableHashKey"
 	  type = "S"
 	}
   
 	replica {
 	  region_name = "us-east-2"
 	}
   
 	replica {
 	  region_name = "us-west-2"
 	}
   }
 
```



### Secure Example

The following example will pass the aws-dynamodb-table-customer-key check.
```terraform

 resource "aws_kms_key" "dynamo_db_kms" {
 	enable_key_rotation = true
 }
 
 resource "aws_dynamodb_table" "good_example" {
 	name             = "example"
 	hash_key         = "TestTableHashKey"
 	billing_mode     = "PAY_PER_REQUEST"
 	stream_enabled   = true
 	stream_view_type = "NEW_AND_OLD_IMAGES"
   
 	attribute {
 	  name = "TestTableHashKey"
 	  type = "S"
 	}
   
 	replica {
 	  region_name = "us-east-2"
 	}
   
 	replica {
 	  region_name = "us-west-2"
 	}
 
 	server_side_encryption {
 		enabled     = true
 		kms_key_arn = aws_kms_key.dynamo_db_kms.key_id
 	}
   }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table#server_side_encryption](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table#server_side_encryption){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html){:target="_blank" rel="nofollow noreferrer noopener"}




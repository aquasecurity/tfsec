---
title: Point in time recovery should be enabled to protect DynamoDB table
---

# Point in time recovery should be enabled to protect DynamoDB table

### Default Severity: <span class="severity medium">medium</span>

### Explanation

DynamoDB tables should be protected against accidentally or malicious write/delete actions by ensuring that there is adequate protection.

By enabling point-in-time-recovery you can restore to a known point in the event of loss of data.

### Possible Impact
Accidental or malicious writes and deletes can't be rolled back

### Suggested Resolution
Enable point in time recovery


### Insecure Example

The following example will fail the aws-dynamodb-enable-recovery check.
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
 }
 
```



### Secure Example

The following example will pass the aws-dynamodb-enable-recovery check.
```terraform

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
 
 	point_in_time_recovery {
 		enabled = true
 	}
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table#point_in_time_recovery](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table#point_in_time_recovery){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html){:target="_blank" rel="nofollow noreferrer noopener"}




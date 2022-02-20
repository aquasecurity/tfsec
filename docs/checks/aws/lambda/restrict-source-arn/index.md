---
title: Ensure that lambda function permission has a source arn specified
---

# Ensure that lambda function permission has a source arn specified

### Default Severity: <span class="severity critical">critical</span>

### Explanation

When the principal is an AWS service, the ARN of the specific resource within that service to grant permission to. 

Without this, any resource from principal will be granted permission – even if that resource is from another account. 

For S3, this should be the ARN of the S3 Bucket. For CloudWatch Events, this should be the ARN of the CloudWatch Events Rule. For API Gateway, this should be the ARN of the API

### Possible Impact
Not providing the source ARN allows any resource from principal, even from other accounts

### Suggested Resolution
Always provide a source arn for Lambda permissions


### Insecure Example

The following example will fail the aws-lambda-restrict-source-arn check.
```terraform

resource "aws_lambda_permission" "bad_example" {
	statement_id = "AllowExecutionFromSNS"
	action = "lambda:InvokeFunction"
	function_name = aws_lambda_function.func.function_name
	principal = "sns.amazonaws.com"
}
		
```



### Secure Example

The following example will pass the aws-lambda-restrict-source-arn check.
```terraform

resource "aws_lambda_permission" "good_example" {
	statement_id = "AllowExecutionFromSNS"
	action = "lambda:InvokeFunction"
	function_name = aws_lambda_function.func.function_name
	principal = "sns.amazonaws.com"
	source_arn = aws_sns_topic.default.arn
}
		
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html){:target="_blank" rel="nofollow noreferrer noopener"}




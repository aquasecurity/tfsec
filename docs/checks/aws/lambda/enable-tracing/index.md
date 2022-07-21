---
title: Lambda functions should have X-Ray tracing enabled
---

# Lambda functions should have X-Ray tracing enabled

### Default Severity: <span class="severity low">low</span>

### Explanation

X-Ray tracing enables end-to-end debugging and analysis of all function activity. This will allow for identifying bottlenecks, slow downs and timeouts.

### Possible Impact
Without full tracing enabled it is difficult to trace the flow of logs

### Suggested Resolution
Enable tracing


### Insecure Example

The following example will fail the aws-lambda-enable-tracing check.
```terraform

 resource "aws_iam_role" "iam_for_lambda" {
   name = "iam_for_lambda"
 
   assume_role_policy = <<EOF
 {
   "Version": "2012-10-17",
   "Statement": [
     {
       "Action": "sts:AssumeRole",
       "Principal": {
         "Service": "lambda.amazonaws.com"
       },
       "Effect": "Allow",
       "Sid": ""
     }
   ]
 }
 EOF
 }
 
 resource "aws_lambda_function" "bad_example" {
   filename      = "lambda_function_payload.zip"
   function_name = "lambda_function_name"
   role          = aws_iam_role.iam_for_lambda.arn
   handler       = "exports.test"
 
   # The filebase64sha256() function is available in Terraform 0.11.12 and later
   # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
   # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
   source_code_hash = filebase64sha256("lambda_function_payload.zip")
 
   runtime = "nodejs12.x"
 
   environment {
     variables = {
       foo = "bar"
     }
   }
   tracing_config {
     mode = "Passthrough"
   }
 }
 
```



### Secure Example

The following example will pass the aws-lambda-enable-tracing check.
```terraform

 resource "aws_iam_role" "iam_for_lambda" {
   name = "iam_for_lambda"
 
   assume_role_policy = <<EOF
 {
   "Version": "2012-10-17",
   "Statement": [
     {
       "Action": "sts:AssumeRole",
       "Principal": {
         "Service": "lambda.amazonaws.com"
       },
       "Effect": "Allow",
       "Sid": ""
     }
   ]
 }
 EOF
 }
 
 resource "aws_lambda_function" "good_example" {
   filename      = "lambda_function_payload.zip"
   function_name = "lambda_function_name"
   role          = aws_iam_role.iam_for_lambda.arn
   handler       = "exports.test"
 
   # The filebase64sha256() function is available in Terraform 0.11.12 and later
   # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
   # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
   source_code_hash = filebase64sha256("lambda_function_payload.zip")
 
   runtime = "nodejs12.x"
 
   environment {
     variables = {
       foo = "bar"
     }
   }
   tracing_config {
     mode = "Active"
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function#mode](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function#mode){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html](https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html){:target="_blank" rel="nofollow noreferrer noopener"}




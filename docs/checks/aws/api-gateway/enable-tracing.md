---
title: API Gateway must have X-Ray tracing enabled
---

# API Gateway must have X-Ray tracing enabled

### Default Severity: <span class="severity low">low</span>

### Explanation

X-Ray tracing enables end-to-end debugging and analysis of all API Gateway HTTP requests.

### Possible Impact
Without full tracing enabled it is difficult to trace the flow of logs

### Suggested Resolution
Enable tracing


### Insecure Example

The following example will fail the aws-api-gateway-enable-tracing check.
```terraform

 resource "aws_api_gateway_rest_api" "test" {
	
 }

 resource "aws_api_gateway_stage" "bad_example" {
   stage_name    = "prod"
   rest_api_id   = aws_api_gateway_rest_api.test.id
   deployment_id = aws_api_gateway_deployment.test.id
   xray_tracing_enabled = false
 }
 
```



### Secure Example

The following example will pass the aws-api-gateway-enable-tracing check.
```terraform

 resource "aws_api_gateway_rest_api" "test" {
	
 }

 resource "aws_api_gateway_stage" "good_example" {
   stage_name    = "prod"
   rest_api_id   = aws_api_gateway_rest_api.test.id
   deployment_id = aws_api_gateway_deployment.test.id
   xray_tracing_enabled = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage#xray_tracing_enabled](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage#xray_tracing_enabled){:target="_blank" rel="nofollow noreferrer noopener"}




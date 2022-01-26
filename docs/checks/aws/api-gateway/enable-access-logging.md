---
title: API Gateway stages for V1 and V2 should have access logging enabled
---

# API Gateway stages for V1 and V2 should have access logging enabled

### Default Severity: <span class="severity medium">medium</span>

### Explanation

API Gateway stages should have access log settings block configured to track all access to a particular stage. This should be applied to both v1 and v2 gateway stages.

### Possible Impact
Logging provides vital information about access and usage

### Suggested Resolution
Enable logging for API Gateway stages


### Insecure Example

The following example will fail the aws-api-gateway-enable-access-logging check.
```terraform

 resource "aws_apigatewayv2_stage" "bad_example" {
   api_id = aws_apigatewayv2_api.example.id
   name   = "example-stage"
 }
 
 resource "aws_apigatewayv2_stage" "bad_example" {
   deployment_id = aws_api_gateway_deployment.example.id
   rest_api_id   = aws_api_gateway_rest_api.example.id
   stage_name    = "example"
 }
 
```



### Secure Example

The following example will pass the aws-api-gateway-enable-access-logging check.
```terraform

 resource "aws_apigatewayv2_stage" "good_example" {
   api_id = aws_apigatewayv2_api.example.id
   name   = "example-stage"
 
   access_log_settings {
    destination_arn = "arn:aws:logs:region:0123456789:log-group:access_logging"
    format          = "json"
   }
 }
 
 resource "aws_api_gateway_stage" "good_example" {
   deployment_id = aws_api_gateway_deployment.example.id
   rest_api_id   = aws_api_gateway_rest_api.example.id
   stage_name    = "example"
 
   access_log_settings {
     destination_arn = "arn:aws:logs:region:0123456789:log-group:access_logging"
     format          = "json"
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/apigatewayv2_stage#access_log_settings](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/apigatewayv2_stage#access_log_settings){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html){:target="_blank" rel="nofollow noreferrer noopener"}




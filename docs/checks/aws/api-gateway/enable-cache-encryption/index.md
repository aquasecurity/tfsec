---
title: API Gateway must have cache enabled
---

# API Gateway must have cache enabled

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Method cache encryption ensures that any sensitive data in the cache is not vulnerable to compromise in the event of interception

### Possible Impact
Data stored in the cache that is unencrypted may be vulnerable to compromise

### Suggested Resolution
Enable cache encryption


### Insecure Example

The following example will fail the aws-api-gateway-enable-cache-encryption check.
```terraform

 resource "aws_api_gateway_rest_api" "example" {
	
 }

 resource "aws_api_gateway_stage" "example" {
	rest_api_id = aws_api_gateway_rest_api.example.id
 }

 resource "aws_api_gateway_method_settings" "bad_example" {
   rest_api_id = aws_api_gateway_rest_api.example.id
   stage_name  = aws_api_gateway_stage.example.stage_name
   method_path = "path1/GET"
 
   settings {
     metrics_enabled = true
     logging_level   = "INFO"
     caching_enabled = true
     cache_data_encrypted = false
   }
 }
 
```



### Secure Example

The following example will pass the aws-api-gateway-enable-cache-encryption check.
```terraform

 resource "aws_api_gateway_rest_api" "example" {
	
 }

 resource "aws_api_gateway_stage" "example" {

 }

 resource "aws_api_gateway_method_settings" "good_example" {
   rest_api_id = aws_api_gateway_rest_api.example.id
   stage_name  = aws_api_gateway_stage.example.stage_name
   method_path = "path1/GET"
 
   settings {
     metrics_enabled = true
     logging_level   = "INFO"
     caching_enabled = true
     cache_data_encrypted = true
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method_settings#cache_data_encrypted](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method_settings#cache_data_encrypted){:target="_blank" rel="nofollow noreferrer noopener"}




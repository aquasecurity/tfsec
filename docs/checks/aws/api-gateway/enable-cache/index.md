---
title: Ensure that response caching is enabled for your Amazon API Gateway REST APIs.
---

# Ensure that response caching is enabled for your Amazon API Gateway REST APIs.

### Default Severity: <span class="severity low">low</span>

### Explanation

A REST API in API Gateway is a collection of resources and methods that are integrated with backend HTTP endpoints, Lambda functions, or other AWS services. You can enable API caching in Amazon API Gateway to cache your endpoint responses. With caching, you can reduce the number of calls made to your endpoint and also improve the latency of requests to your API.

### Possible Impact
Reduce the number of calls made to your API endpoint and also improve the latency of requests to your API with response caching.

### Suggested Resolution
Enable cache


### Insecure Example

The following example will fail the aws-api-gateway-enable-cache check.
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
     caching_enabled = false
   }
 }
 
```



### Secure Example

The following example will pass the aws-api-gateway-enable-cache check.
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
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method_settings#cache_enabled](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method_settings#cache_enabled){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html){:target="_blank" rel="nofollow noreferrer noopener"}




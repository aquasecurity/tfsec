---
title: No unauthorized access to API Gateway methods
---

# No unauthorized access to API Gateway methods

### Default Severity: <span class="severity low">low</span>

### Explanation

API Gateway methods should generally be protected by authorization or api key. OPTION verb calls can be used without authorization

### Possible Impact
API gateway methods can be accessed without authorization.

### Suggested Resolution
Use and authorization method or require API Key


### Insecure Example

The following example will fail the aws-api-gateway-no-public-access check.
```terraform

 resource "aws_api_gateway_rest_api" "MyDemoAPI" {
	
 }

 resource "aws_api_gateway_resource" "MyDemoResource" {
	rest_api_id      = aws_api_gateway_rest_api.MyDemoAPI.id
 }

 resource "aws_api_gateway_method" "bad_example" {
   rest_api_id   = aws_api_gateway_rest_api.MyDemoAPI.id
   resource_id   = aws_api_gateway_resource.MyDemoResource.id
   http_method   = "GET"
   authorization = "NONE"
 }
 
```



### Secure Example

The following example will pass the aws-api-gateway-no-public-access check.
```terraform

 resource "aws_api_gateway_rest_api" "MyDemoAPI" {
	
 }

 resource "aws_api_gateway_resource" "MyDemoResource" {
	rest_api_id      = aws_api_gateway_rest_api.MyDemoAPI.id
 }

 resource "aws_api_gateway_method" "good_example" {
   rest_api_id   = aws_api_gateway_rest_api.MyDemoAPI.id
   resource_id   = aws_api_gateway_resource.MyDemoResource.id
   http_method   = "GET"
   authorization = "AWS_IAM"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method#authorization](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method#authorization){:target="_blank" rel="nofollow noreferrer noopener"}




package apigateway

import (
	"github.com/aquasecurity/defsec/rules/aws/apigateway"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS061",
		BadExample: []string{`
 resource "aws_apigatewayv2_stage" "bad_example" {
   api_id = aws_apigatewayv2_api.example.id
   name   = "example-stage"
 }
 
 resource "aws_api_gateway_stage" "bad_example" {
   deployment_id = aws_api_gateway_deployment.example.id
   rest_api_id   = aws_api_gateway_rest_api.example.id
   stage_name    = "example"
 }
 `},
		GoodExample: []string{`
 resource "aws_apigatewayv2_stage" "good_example" {
   api_id = aws_apigatewayv2_api.example.id
   name   = "example-stage"
 
   access_log_settings {
     destination_arn = ""
     format          = ""
   }
 }
 
 resource "aws_api_gateway_stage" "good_example" {
   deployment_id = aws_api_gateway_deployment.example.id
   rest_api_id   = aws_api_gateway_rest_api.example.id
   stage_name    = "example"
 
   access_log_settings {
     destination_arn = ""
     format          = ""
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/apigatewayv2_stage#access_log_settings",
		},
		Base: apigateway.CheckEnableAccessLogging,
	})
}

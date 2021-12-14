package apigateway
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AWSMissingSecurityPolicy(t *testing.T) {
 	expectedCode := "aws-api-gateway-use-secure-tls-policy"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "check aws_api_gateway_domain_name with outdated policy",
 			source: `
 resource "aws_api_gateway_domain_name" "my-resource" {
 	security_policy = "TLS_1_0"
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check aws_api_gateway_domain_name with empty security policy",
 			source: `
 resource "aws_api_gateway_domain_name" "my-resource" {
 	security_policy = ""
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check aws_api_gateway_domain_name without security policy",
 			source: `
 resource "aws_api_gateway_domain_name" "my-resource" {
  domain=""
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check aws_api_gateway_domain_name with ok policy",
 			source: `
 resource "aws_api_gateway_domain_name" "my-resource" {
 	security_policy = "TLS_1_2"
 }`,
 			mustExcludeResultCode: expectedCode,
 		},
 	}
 
 	for _, test := range tests {
 		t.Run(test.name, func(t *testing.T) {
 
 			results := testutil.ScanHCL(test.source, t)
 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
 		})
 	}
 
 }

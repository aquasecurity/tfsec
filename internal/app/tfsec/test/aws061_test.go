package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSAPIGatewayHasAccessLoggingEnabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "test missing access log settings has error v2",
			source: `
resource "aws_apigatewayv2_stage" "bad_example" {
  api_id = aws_apigatewayv2_api.example.id
  name   = "example-stage"
}
`,
			mustIncludeResultCode: rules.AWSAPIGatewayHasAccessLoggingEnabled,
		},
		{
			name: "test missing access log settings has error",
			source: `
resource "aws_api_gateway_stage" "bad_example" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "example"
}
`,
			mustIncludeResultCode: rules.AWSAPIGatewayHasAccessLoggingEnabled,
		},
		{
			name: "test access log settings present has no error v2",
			source: `
resource "aws_apigatewayv2_stage" "good_example" {
  api_id = aws_apigatewayv2_api.example.id
  name   = "example-stage"

  access_log_settings {
    destination_arn = ""
    format          = ""
  }
}
`,
			mustExcludeResultCode: rules.AWSAPIGatewayHasAccessLoggingEnabled,
		},
		{
			name: "test access log settings present has no error",
			source: `
resource "aws_api_gateway_stage" "good_example" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "example"

  access_log_settings {
    destination_arn = ""
    format          = ""
  }
}
`,
			mustExcludeResultCode: rules.AWSAPIGatewayHasAccessLoggingEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

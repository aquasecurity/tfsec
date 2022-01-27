package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  apigateway.APIGateway
	}{
		{
			name: "basic",
			terraform: `
resource "aws_api_gateway_rest_api" "MyDemoAPI" {
  name        = "MyDemoAPI"
  description = "This is my API for demonstration purposes"
}

resource "aws_api_gateway_method" "example" {
    rest_api_id = aws_api_gateway_rest_api.MyDemoAPI.id
    http_method      = "GET"
    authorization    = "NONE"
}
resource "aws_apigatewayv2_api" "example" {
    name = "tfsec"
    protocol_type = "HTTP"
}

resource "aws_apigatewayv2_stage" "example" {
    api_id = aws_apigatewayv2_api.example.id
    name = "tfsec" 
    access_log_settings {
        destination_arn = "arn:123"
    }
}

resource "aws_api_gateway_domain_name" "example" {
    domain_name = "v1.com"
    security_policy = "TLS_1_0"
}

resource "aws_apigatewayv2_domain_name" "example" {
    domain_name = "v2.com"
    domain_name_configuration {
        security_policy = "TLS_1_2"
    }
}
`,
			expected: apigateway.APIGateway{
				APIs: []apigateway.API{
					{
						Name:         testutil.String("MyDemoAPI"),
						Version:      testutil.Int(1),
						ProtocolType: testutil.String("REST"),
						RESTMethods: []apigateway.RESTMethod{
							{
								HTTPMethod:        testutil.String("GET"),
								AuthorizationType: testutil.String("NONE"),
								APIKeyRequired:    testutil.Bool(false),
							},
						},
					},
					{
						Name:         testutil.String("tfsec"),
						Version:      testutil.Int(2),
						ProtocolType: testutil.String("HTTP"),
						Stages: []apigateway.Stage{
							{
								Version: testutil.Int(2),
								Name:    testutil.String("tfsec"),
								AccessLogging: apigateway.AccessLogging{
									CloudwatchLogGroupARN: testutil.String("arn:123"),
								},
							},
						},
					},
				},
				DomainNames: []apigateway.DomainName{
					{
						Name:           testutil.String("v1.com"),
						Version:        testutil.Int(1),
						SecurityPolicy: testutil.String("TLS_1_0"),
					},
					{
						Name:           testutil.String("v2.com"),
						Version:        testutil.Int(2),
						SecurityPolicy: testutil.String("TLS_1_2"),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

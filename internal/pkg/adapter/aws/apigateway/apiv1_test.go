package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_adaptAPIMethodsV1(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []apigateway.RESTMethod
	}{
		{
			name: "defaults",
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
`,
			expected: []apigateway.RESTMethod{
				{
					HTTPMethod:        testutil.String("GET"),
					AuthorizationType: testutil.String("NONE"),
					APIKeyRequired:    testutil.Bool(false),
				},
			},
		},
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
    api_key_required = true
}
`,
			expected: []apigateway.RESTMethod{
				{
					HTTPMethod:        testutil.String("GET"),
					AuthorizationType: testutil.String("NONE"),
					APIKeyRequired:    testutil.Bool(true),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			restApiBlock := modules.GetBlocks()[0]
			adapted := adaptAPIMethodsV1(modules, restApiBlock)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptAPIsV1(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []apigateway.API
	}{
		{
			name: "defaults",
			terraform: `
resource "aws_api_gateway_rest_api" "example" {
    
}
`,
			expected: []apigateway.API{
				{
					Name:         testutil.String(""),
					Version:      testutil.Int(1),
					ProtocolType: testutil.String("REST"),
				},
			},
		},
		{
			name: "full",
			terraform: `
resource "aws_api_gateway_rest_api" "example" {
   name = "tfsec" 
}
`,
			expected: []apigateway.API{
				{
					Name:         testutil.String("tfsec"),
					Version:      testutil.Int(1),
					ProtocolType: testutil.String("REST"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptAPIsV1(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

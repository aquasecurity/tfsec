package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_adaptAPIsV2(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []apigateway.API
	}{
		{
			name: "defaults",
			terraform: `
resource "aws_apigatewayv2_api" "example" {
    protocol_type = "HTTP"
}
`,
			expected: []apigateway.API{
				{
					Name:         testutil.String(""),
					Version:      testutil.Int(2),
					ProtocolType: testutil.String("HTTP"),
				},
			},
		},
		{
			name: "full",
			terraform: `
resource "aws_apigatewayv2_api" "example" {
    name = "tfsec"
    protocol_type = "HTTP"
}
`,
			expected: []apigateway.API{
				{
					Name:         testutil.String("tfsec"),
					Version:      testutil.Int(2),
					ProtocolType: testutil.String("HTTP"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptAPIsV2(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptStageV2(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  apigateway.Stage
	}{
		{
			name: "defaults",
			terraform: `
resource "aws_apigatewayv2_stage" "example" {
    
}
`,
			expected: apigateway.Stage{
				Name:    testutil.String(""),
				Version: testutil.Int(2),
				AccessLogging: apigateway.AccessLogging{
					CloudwatchLogGroupARN: testutil.String(""),
				},
				RESTMethodSettings: apigateway.RESTMethodSettings{
					CacheDataEncrypted: testutil.Bool(true),
				},
			},
		},
		{
			name: "basics",
			terraform: `
resource "aws_apigatewayv2_stage" "example" {
    name = "tfsec" 
    access_log_settings {
        destination_arn = "arn:123"
    }
}
`,
			expected: apigateway.Stage{
				Name:    testutil.String("tfsec"),
				Version: testutil.Int(2),
				AccessLogging: apigateway.AccessLogging{
					CloudwatchLogGroupARN: testutil.String("arn:123"),
				},
				RESTMethodSettings: apigateway.RESTMethodSettings{
					CacheDataEncrypted: testutil.Bool(true),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptStageV2(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_adaptDomainNamesV2(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []apigateway.DomainName
	}{
		{
			name: "defaults",
			terraform: `
resource "aws_apigatewayv2_domain_name" "example" {
}
`,
			expected: []apigateway.DomainName{
				{
					Name:           testutil.String(""),
					Version:        testutil.Int(2),
					SecurityPolicy: testutil.String("TLS_1_0"),
				},
			},
		},
		{
			name: "fully populated",
			terraform: `
resource "aws_apigatewayv2_domain_name" "example" {
                domain_name = "testing.com"
                domain_name_configuration {
                    security_policy = "TLS_1_2"
                }
}
`,
			expected: []apigateway.DomainName{
				{
					Name:           testutil.String("testing.com"),
					Version:        testutil.Int(2),
					SecurityPolicy: testutil.String("TLS_1_2"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptDomainNamesV2(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

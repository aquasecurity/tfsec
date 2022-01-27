package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_adaptDomainNamesV1(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []apigateway.DomainName
	}{
		{
			name: "defaults",
			terraform: `
resource "aws_api_gateway_domain_name" "example" {
}
`,
			expected: []apigateway.DomainName{
				{
					Name:           testutil.String(""),
					Version:        testutil.Int(1),
					SecurityPolicy: testutil.String("TLS_1_0"),
				},
			},
		},
		{
			name: "basic",
			terraform: `
resource "aws_api_gateway_domain_name" "example" {
    domain_name = "testing.com"
    security_policy = "TLS_1_2"
}
`,
			expected: []apigateway.DomainName{
				{
					Name:           testutil.String("testing.com"),
					Version:        testutil.Int(1),
					SecurityPolicy: testutil.String("TLS_1_2"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptDomainNamesV1(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

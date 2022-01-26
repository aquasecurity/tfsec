package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
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
					Name:           types.String("", types.NewTestMetadata()),
					Version:        types.Int(2, types.NewTestMetadata()),
					SecurityPolicy: types.String("TLS_1_0", types.NewTestMetadata()),
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
					Name:           types.String("testing.com", types.NewTestMetadata()),
					Version:        types.Int(2, types.NewTestMetadata()),
					SecurityPolicy: types.String("TLS_1_2", types.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptDomainNamesV2(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  apigateway.APIGateway
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: apigateway.APIGateway{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := Adapt(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptAPIs(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []apigateway.API
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []apigateway.API{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptAPIs(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptDomainNames(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []apigateway.DomainName
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []apigateway.DomainName{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptDomainNames(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

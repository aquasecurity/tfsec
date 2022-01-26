package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_adaptAPIMethodsV1(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []apigateway.RESTMethod
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []apigateway.RESTMethod{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptAPIMethodsV1(modules, modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptAPIsV1(t *testing.T) {
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
			adapted := adaptAPIsV1(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

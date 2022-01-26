package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_adaptAPIsV2(t *testing.T) {
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
			adapted := adaptAPIsV2(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptStageV2(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  apigateway.Stage
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: apigateway.Stage{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptStageV2(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

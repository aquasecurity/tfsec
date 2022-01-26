package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_adaptDomainNamesV1(t *testing.T) {
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
			adapted := adaptDomainNamesV1(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

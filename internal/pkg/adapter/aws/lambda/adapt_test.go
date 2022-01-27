package lambda

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/lambda"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  lambda.Lambda
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: lambda.Lambda{},
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

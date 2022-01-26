package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_adaptPasswordPolicy(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  iam.PasswordPolicy
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: iam.PasswordPolicy{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptPasswordPolicy(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

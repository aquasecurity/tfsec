package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/google/iam"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_AdaptMember(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  iam.Member
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: iam.Member{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := AdaptMember(modules.GetBlocks()[0], modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_AdaptBinding(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  iam.Binding
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: iam.Binding{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := AdaptBinding(modules.GetBlocks()[0], modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

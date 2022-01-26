package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_adaptProjectMetadata(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  compute.ProjectMetadata
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: compute.ProjectMetadata{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptProjectMetadata(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

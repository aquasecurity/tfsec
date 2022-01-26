package spaces

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/digitalocean/spaces"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  spaces.Spaces
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: spaces.Spaces{},
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

func Test_adaptBuckets(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []spaces.Bucket
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []spaces.Bucket{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptBuckets(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

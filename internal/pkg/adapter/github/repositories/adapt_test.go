package repositories

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/github"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []github.Repository
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []github.Repository{},
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

func Test_adaptRepositories(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []github.Repository
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []github.Repository{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptRepositories(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptRepository(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  github.Repository
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: github.Repository{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptRepository(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

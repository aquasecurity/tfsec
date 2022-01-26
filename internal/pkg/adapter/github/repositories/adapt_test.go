package repositories

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/github"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
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
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := Adapt(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
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
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptRepositories(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
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
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptRepository(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

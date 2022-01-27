package efs

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/efs"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  efs.EFS
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: efs.EFS{},
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

func Test_adaptFileSystems(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []efs.FileSystem
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []efs.FileSystem{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptFileSystems(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptFileSystem(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  efs.FileSystem
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: efs.FileSystem{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptFileSystem(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

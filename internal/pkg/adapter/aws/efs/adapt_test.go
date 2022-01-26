package efs

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/efs"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
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
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := Adapt(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
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
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptFileSystems(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
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
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptFileSystem(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

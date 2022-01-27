package workspaces

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/workspaces"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  workspaces.WorkSpaces
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: workspaces.WorkSpaces{},
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

func Test_adaptWorkspaces(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []workspaces.WorkSpace
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []workspaces.WorkSpace{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptWorkspaces(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptWorkspace(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  workspaces.WorkSpace
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: workspaces.WorkSpace{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptWorkspace(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

package authorization

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/authorization"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  authorization.Authorization
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: authorization.Authorization{},
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

func Test_adaptRoleDefinitions(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []authorization.RoleDefinition
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []authorization.RoleDefinition{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptRoleDefinitions(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptRoleDefinition(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  authorization.RoleDefinition
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: authorization.RoleDefinition{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptRoleDefinition(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

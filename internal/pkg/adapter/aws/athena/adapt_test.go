package athena

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/athena"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  athena.Athena
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: athena.Athena{},
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

func Test_adaptDatabases(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []athena.Database
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []athena.Database{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptDatabases(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptWorkgroups(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []athena.Workgroup
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []athena.Workgroup{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptWorkgroups(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptDatabase(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  athena.Database
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: athena.Database{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptDatabase(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptWorkgroup(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  athena.Workgroup
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: athena.Workgroup{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptWorkgroup(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

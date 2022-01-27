package sql

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/google/sql"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  sql.SQL
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: sql.SQL{},
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

func Test_adaptInstances(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []sql.DatabaseInstance
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []sql.DatabaseInstance{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptInstances(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptInstance(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  sql.DatabaseInstance
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: sql.DatabaseInstance{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptInstance(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptFlags(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  sql.Flags
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: sql.Flags{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptFlags(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptIPConfig(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  sql.IPConfiguration
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: sql.IPConfiguration{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptIPConfig(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

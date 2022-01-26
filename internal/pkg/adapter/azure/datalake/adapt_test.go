package datalake

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/datalake"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  datalake.DataLake
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: datalake.DataLake{},
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

func Test_adaptStores(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []datalake.Store
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []datalake.Store{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptStores(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptStore(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  datalake.Store
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: datalake.Store{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptStore(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

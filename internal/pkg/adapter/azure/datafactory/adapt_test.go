package datafactory

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/datafactory"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  datafactory.DataFactory
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: datafactory.DataFactory{},
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

func Test_adaptFactories(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []datafactory.Factory
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []datafactory.Factory{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptFactories(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptFactory(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  datafactory.Factory
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: datafactory.Factory{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptFactory(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

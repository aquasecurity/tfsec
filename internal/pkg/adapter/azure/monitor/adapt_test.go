package monitor

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/monitor"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  monitor.Monitor
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: monitor.Monitor{},
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

func Test_adaptLogProfiles(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []monitor.LogProfile
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []monitor.LogProfile{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptLogProfiles(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptLogProfile(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  monitor.LogProfile
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: monitor.LogProfile{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptLogProfile(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

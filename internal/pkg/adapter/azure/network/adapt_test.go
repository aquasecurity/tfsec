package network

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/network"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  network.Network
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: network.Network{},
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

func Test_adaptWatcherLogs(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []network.NetworkWatcherFlowLog
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []network.NetworkWatcherFlowLog{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptWatcherLogs(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptWatcherLog(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  network.NetworkWatcherFlowLog
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: network.NetworkWatcherFlowLog{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptWatcherLog(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

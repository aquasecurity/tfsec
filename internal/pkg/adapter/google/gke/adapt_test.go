package gke

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/google/gke"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  gke.GKE
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: gke.GKE{},
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

func Test_adaptNodeConfig(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  gke.NodeConfig
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: gke.NodeConfig{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptNodeConfig(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptMasterAuth(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  gke.MasterAuth
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: gke.MasterAuth{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptMasterAuth(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

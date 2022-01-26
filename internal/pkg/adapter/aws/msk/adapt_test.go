package msk

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/msk"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  msk.MSK
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: msk.MSK{},
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

func Test_adaptClusters(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []msk.Cluster
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []msk.Cluster{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptClusters(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptCluster(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  msk.Cluster
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: msk.Cluster{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptCluster(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

package documentdb

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/documentdb"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  documentdb.DocumentDB
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: documentdb.DocumentDB{},
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
		expected  []documentdb.Cluster
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []documentdb.Cluster{},
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
		expected  documentdb.Cluster
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: documentdb.Cluster{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptCluster(modules.GetBlocks()[0], modules[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

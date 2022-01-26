package bigquery

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/google/bigquery"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  bigquery.BigQuery
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: bigquery.BigQuery{},
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

func Test_adaptDatasets(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []bigquery.Dataset
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []bigquery.Dataset{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptDatasets(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptDataset(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  bigquery.Dataset
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: bigquery.Dataset{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptDataset(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

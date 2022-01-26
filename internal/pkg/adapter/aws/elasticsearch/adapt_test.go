package elasticsearch

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/elasticsearch"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  elasticsearch.Elasticsearch
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: elasticsearch.Elasticsearch{},
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

func Test_adaptDomains(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []elasticsearch.Domain
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []elasticsearch.Domain{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptDomains(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptDomain(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  elasticsearch.Domain
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: elasticsearch.Domain{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptDomain(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

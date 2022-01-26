package cloudfront

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/cloudfront"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  cloudfront.Cloudfront
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: cloudfront.Cloudfront{},
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

func Test_adaptDistributions(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []cloudfront.Distribution
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []cloudfront.Distribution{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptDistributions(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptDistribution(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  cloudfront.Distribution
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: cloudfront.Distribution{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptDistribution(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

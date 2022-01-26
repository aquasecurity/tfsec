package cloudwatch

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/cloudwatch"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  cloudwatch.CloudWatch
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: cloudwatch.CloudWatch{},
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

func Test_adaptLogGroups(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []cloudwatch.LogGroup
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []cloudwatch.LogGroup{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptLogGroups(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptLogGroup(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  cloudwatch.LogGroup
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: cloudwatch.LogGroup{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptLogGroup(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

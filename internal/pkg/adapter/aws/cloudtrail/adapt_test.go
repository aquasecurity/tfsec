package cloudtrail

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/cloudtrail"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  cloudtrail.CloudTrail
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: cloudtrail.CloudTrail{},
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

func Test_adaptTrails(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []cloudtrail.Trail
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []cloudtrail.Trail{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptTrails(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptTrail(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  cloudtrail.Trail
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: cloudtrail.Trail{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptTrail(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

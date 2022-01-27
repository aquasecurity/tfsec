package ebs

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/ebs"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  ebs.EBS
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: ebs.EBS{},
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

func Test_adaptVolumes(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []ebs.Volume
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []ebs.Volume{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptVolumes(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptVolume(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  ebs.Volume
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: ebs.Volume{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptVolume(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

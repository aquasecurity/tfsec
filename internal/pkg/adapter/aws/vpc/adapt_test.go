package vpc

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/vpc"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  vpc.VPC
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: vpc.VPC{},
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

func Test_adaptDefaultVPCs(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []vpc.DefaultVPC
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []vpc.DefaultVPC{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptDefaultVPCs(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptSGRule(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  vpc.SecurityGroupRule
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: vpc.SecurityGroupRule{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptSGRule(modules.GetBlocks()[0], modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptNetworkACLRule(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  vpc.NetworkACLRule
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: vpc.NetworkACLRule{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptNetworkACLRule(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

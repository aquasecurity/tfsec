package ssm

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/ssm"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  ssm.SSM
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: ssm.SSM{},
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

func Test_adaptSecrets(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []ssm.Secret
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []ssm.Secret{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptSecrets(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptSecret(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  ssm.Secret
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: ssm.Secret{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptSecret(modules.GetBlocks()[0], modules[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

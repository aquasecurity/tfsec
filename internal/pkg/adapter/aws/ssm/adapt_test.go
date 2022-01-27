package ssm

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/ssm"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
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
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
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
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptSecrets(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
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
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptSecret(modules.GetBlocks()[0], modules[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

package keyvault

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/keyvault"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  keyvault.KeyVault
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: keyvault.KeyVault{},
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

func Test_adaptSecret(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  keyvault.Secret
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: keyvault.Secret{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptSecret(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptKey(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  keyvault.Key
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: keyvault.Key{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptKey(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

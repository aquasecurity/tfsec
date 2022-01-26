package storage

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/storage"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  storage.Storage
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: storage.Storage{},
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

func Test_adaptAccounts(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []storage.Account
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []storage.Account{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted, _, _ := adaptAccounts(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptAccount(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  storage.Account
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: storage.Account{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptAccount(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptContainer(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  storage.Container
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: storage.Container{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptContainer(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptNetworkRule(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  storage.NetworkRule
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: storage.NetworkRule{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptNetworkRule(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

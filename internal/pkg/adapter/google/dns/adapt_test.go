package dns

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/google/dns"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  dns.DNS
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: dns.DNS{},
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

func Test_adaptManagedZones(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []dns.ManagedZone
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []dns.ManagedZone{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptManagedZones(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptManagedZone(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  dns.ManagedZone
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: dns.ManagedZone{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptManagedZone(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptKeySpecs(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  dns.KeySpecs
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: dns.KeySpecs{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptKeySpecs(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

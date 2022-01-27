package securitycenter

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/securitycenter"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  securitycenter.SecurityCenter
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: securitycenter.SecurityCenter{},
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

func Test_adaptContacts(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []securitycenter.Contact
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []securitycenter.Contact{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptContacts(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptSubscriptions(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []securitycenter.SubscriptionPricing
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []securitycenter.SubscriptionPricing{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptSubscriptions(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptContact(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  securitycenter.Contact
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: securitycenter.Contact{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptContact(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptSubscription(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  securitycenter.SubscriptionPricing
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: securitycenter.SubscriptionPricing{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptSubscription(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

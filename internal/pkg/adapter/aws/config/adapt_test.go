package config

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/config"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  config.Config
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: config.Config{},
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

func Test_adaptConfigurationAggregrator(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  config.ConfigurationAggregrator
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: config.ConfigurationAggregrator{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptConfigurationAggregrator(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

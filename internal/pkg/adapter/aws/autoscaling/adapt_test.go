package autoscaling

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/autoscaling"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  autoscaling.Autoscaling
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: autoscaling.Autoscaling{},
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

func Test_adaptLaunchConfigurations(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []autoscaling.LaunchConfiguration
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []autoscaling.LaunchConfiguration{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptLaunchConfigurations(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptLaunchConfiguration(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  autoscaling.LaunchConfiguration
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: autoscaling.LaunchConfiguration{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptLaunchConfiguration(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

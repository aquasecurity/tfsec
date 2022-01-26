package appservice

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/appservice"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  appservice.AppService
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: appservice.AppService{},
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

func Test_adaptServices(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []appservice.Service
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []appservice.Service{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptServices(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptFunctionApps(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []appservice.FunctionApp
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []appservice.FunctionApp{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptFunctionApps(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptService(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  appservice.Service
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: appservice.Service{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptService(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptFunctionApp(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  appservice.FunctionApp
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: appservice.FunctionApp{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptFunctionApp(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

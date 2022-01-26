package ecs

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/ecs"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  ecs.ECS
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: ecs.ECS{},
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

func Test_adaptClusters(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []ecs.Cluster
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []ecs.Cluster{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptClusters(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptClusterResource(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  ecs.Cluster
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: ecs.Cluster{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptClusterResource(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptClusterSettings(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  ecs.ClusterSettings
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: ecs.ClusterSettings{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptClusterSettings(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptTaskDefinitions(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []ecs.TaskDefinition
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []ecs.TaskDefinition{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptTaskDefinitions(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptTaskDefinitionResource(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  ecs.TaskDefinition
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: ecs.TaskDefinition{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptTaskDefinitionResource(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptVolumes(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []ecs.Volume
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []ecs.Volume{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptVolumes(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptEFSVolumeConfiguration(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  ecs.EFSVolumeConfiguration
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: ecs.EFSVolumeConfiguration{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptEFSVolumeConfiguration(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

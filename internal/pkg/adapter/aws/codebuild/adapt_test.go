package codebuild

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/codebuild"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  codebuild.CodeBuild
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: codebuild.CodeBuild{},
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

func Test_adaptProjects(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []codebuild.Project
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []codebuild.Project{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptProjects(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptProject(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  codebuild.Project
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: codebuild.Project{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptProject(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

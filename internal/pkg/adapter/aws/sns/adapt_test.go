package sns

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/sns"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  sns.SNS
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: sns.SNS{},
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

func Test_adaptTopics(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []sns.Topic
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []sns.Topic{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptTopics(modules)
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptTopic(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  sns.Topic
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: sns.Topic{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptTopic(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptEncryption(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  sns.Encryption
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: sns.Encryption{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutils.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptEncryption(modules.GetBlocks()[0])
			testutils.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

package kinesis

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/kinesis"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  kinesis.Kinesis
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: kinesis.Kinesis{},
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

func Test_adaptStreams(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []kinesis.Stream
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []kinesis.Stream{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptStreams(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptStream(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  kinesis.Stream
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: kinesis.Stream{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptStream(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

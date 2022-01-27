package mq

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/mq"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  mq.MQ
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: mq.MQ{},
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

func Test_adaptBrokers(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []mq.Broker
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []mq.Broker{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptBrokers(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptBroker(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  mq.Broker
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: mq.Broker{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptBroker(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

package sqs

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/sqs"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  sqs.SQS
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: sqs.SQS{},
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

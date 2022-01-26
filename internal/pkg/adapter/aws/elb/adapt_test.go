package elb

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/elb"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutils"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  elb.ELB
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: elb.ELB{},
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

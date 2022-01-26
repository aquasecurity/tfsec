package ec2

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/ec2"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  ec2.EC2
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: ec2.EC2{},
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

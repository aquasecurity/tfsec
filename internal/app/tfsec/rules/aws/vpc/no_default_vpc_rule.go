package vpc

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS082",
		Service:   "vpc",
		ShortCode: "no-default-vpc",
		Documentation: rule.RuleDocumentation{
			Summary: "AWS best practice to not use the default VPC for workflows",
			Explanation: `
Default VPC does not have a lot of the critical security features that standard VPC comes with, new resources should not be created in the default VPC and it should not be present in the Terraform.
`,
			Impact:     "The default VPC does not have critical security features applied",
			Resolution: "Create a non-default vpc for resources to be created in",
			BadExample: []string{`
resource "aws_default_vpc" "default" {
	tags = {
	  Name = "Default VPC"
	}
  }
`},
			GoodExample: []string{`
# no aws default vpc present
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_vpc",
				"https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_default_vpc"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			set.AddResult().
				WithDescription("Resource '%s' should not exist", resourceBlock.FullName())
		},
	})
}

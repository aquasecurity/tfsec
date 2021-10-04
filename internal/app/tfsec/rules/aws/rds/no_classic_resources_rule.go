package rds

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
		LegacyID:  "AWS003",
		Service:   "rds",
		ShortCode: "no-classic-resources",
		Documentation: rule.RuleDocumentation{
			Summary: "AWS Classic resource usage.",
			Explanation: `
AWS Classic resources run in a shared environment with infrastructure owned by other AWS customers. You should run
resources in a VPC instead.
`,
			Impact:     "Classic resources are running in a shared environment with other customers",
			Resolution: "Switch to VPC resources",
			BadExample: []string{`
resource "aws_db_security_group" "bad_example" {
  # ...
}
`},
			GoodExample: []string{`
resource "aws_security_group" "good_example" {
  # ...
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_security_group",
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			set.AddResult().
				WithDescription("Resource '%s' uses EC2 Classic. Use a VPC instead.", resourceBlock.FullName())
		},
	})
}

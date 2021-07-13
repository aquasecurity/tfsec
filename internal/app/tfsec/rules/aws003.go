package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSClassicUsage = "AWS003"
const AWSClassicUsageDescription = "AWS Classic resource usage."
const AWSClassicUsageImpact = "Classic resources are running in a shared environment with other customers"
const AWSClassicUsageResolution = "Switch to VPC resources"
const AWSClassicUsageExplanation = `
AWS Classic resources run in a shared environment with infrastructure owned by other AWS customers. You should run
resources in a VPC instead.
`
const AWSClassicUsageBadExample = `
resource "aws_db_security_group" "bad_example" {
  # ...
}
`
const AWSClassicUsageGoodExample = `
resource "aws_security_group" "good_example" {
  # ...
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSClassicUsage,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSClassicUsageDescription,
			Explanation: AWSClassicUsageExplanation,
			Impact:      AWSClassicUsageImpact,
			Resolution:  AWSClassicUsageResolution,
			BadExample:  AWSClassicUsageBadExample,
			GoodExample: AWSClassicUsageGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			set.Add(
				result.New(resourceBlock).
					WithDescription(fmt.Sprintf("Resource '%s' uses EC2 Classic. Use a VPC instead.", resourceBlock.FullName())).
					WithRange(resourceBlock.Range()),
			)
		},
	})
}

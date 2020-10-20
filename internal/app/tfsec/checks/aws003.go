package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSClassicUsage scanner.RuleCode = "AWS003"
const AWSClassicUsageDescription scanner.RuleSummary = "AWS Classic resource usage."
const AWSClassicUsageExplanation = `
AWS Classic resources run in a shared environment with infrastructure owned by other AWS customers. You should run
resources in a VPC instead.
`
const AWSClassicUsageBadExample = `
resource "aws_db_security_group" "my-group" {
  # ...
}
`
const AWSClassicUsageGoodExample = `
resource "aws_security_group" "allow-db-access" {
  # ...
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSClassicUsage,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSClassicUsageDescription,
			Explanation: AWSClassicUsageExplanation,
			BadExample:  AWSClassicUsageBadExample,
			GoodExample: AWSClassicUsageGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			return []scanner.Result{
				check.NewResult(
					fmt.Sprintf("Resource '%s' uses EC2 Classic. Use a VPC instead.", block.FullName()),
					block.Range(),
					scanner.SeverityError,
				),
			}
		},
	})
}

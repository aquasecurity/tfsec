package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSClassicUsage See https://github.com/tfsec/tfsec#included-checks for check info
const AWSClassicUsage scanner.RuleID = "AWS003"
const AWSClassicUsageDescription scanner.RuleDescription = "AWS Classic resource usage."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSClassicUsage,
		Description:    AWSClassicUsageDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			return []scanner.Result{
				check.NewResult(
					fmt.Sprintf("Resource '%s' uses EC2 Classic. Use a VPC instead.", block.Name()),
					block.Range(),
					scanner.SeverityError,
				),
			}
		},
	})
}

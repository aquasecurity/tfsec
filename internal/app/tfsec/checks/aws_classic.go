package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSClassicUsage See https://github.com/liamg/tfsec#included-checks for check info
const AWSClassicUsage Code = "AWS003"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group"},
		CheckFunc: func(block *parser.Block) []Result {
			return []Result{
				NewResult(
					AWSClassicUsage,
					fmt.Sprintf("Resource '%s' uses EC2 Classic. Use a VPC instead.", block.Name()),
					block.Range(),
				),
			}
		},
	})
}

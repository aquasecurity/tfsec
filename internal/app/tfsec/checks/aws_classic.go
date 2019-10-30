package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

const AWSClassicUsage Code = "AWS003"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group"},
		CheckFunc: func(block *hcl.Block, _ *hcl.EvalContext) []Result {
			return []Result{
				NewResult(
					AWSClassicUsage,
					fmt.Sprintf("Resource '%s' uses EC2 Classic. Use a VPC instead.", getBlockName(block)),
					nil,
				),
			}
		},
	})
}

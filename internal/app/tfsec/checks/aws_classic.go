package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/liamg/tfsec/internal/app/tfsec/models"
)

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group"},
		CheckFunc: func(block *hcl.Block, _ *hcl.EvalContext) []models.Result {
			return []models.Result{
				{
					Description: fmt.Sprintf("Resource '%s' uses EC2 Classic. Use a VPC instead.", getBlockName(block)),
				},
			}
		},
	})
}

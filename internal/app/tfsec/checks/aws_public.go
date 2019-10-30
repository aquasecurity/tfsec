package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/liamg/tfsec/internal/app/tfsec/models"
)

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_instance", "aws_dms_replication_instance", "aws_rds_cluster_instance", "aws_redshift_cluster"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []models.Result {

			if val, attrRange, exists := getAttribute(block, ctx, "publicly_accessible"); exists {
				if val.True() {
					return []models.Result{
						{
							Range:       attrRange,
							Description: fmt.Sprintf("Resource '%s' is exposed publicly.", getBlockName(block)),
						},
					}
				}
			}

			return nil
		},
	})
}

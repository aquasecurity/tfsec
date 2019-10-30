package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

// AWSPubliclyAccessibleResource See https://github.com/liamg/tfsec#included-checks for check info
const AWSPubliclyAccessibleResource Code = "AWS011"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_instance", "aws_dms_replication_instance", "aws_rds_cluster_instance", "aws_redshift_cluster"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {

			if val, attrRange, exists := getAttribute(block, ctx, "publicly_accessible"); exists {
				if val.True() {
					return []Result{
						NewResult(
							AWSPubliclyAccessibleResource,
							fmt.Sprintf("Resource '%s' is exposed publicly.", getBlockName(block)),
							attrRange,
						),
					}
				}
			}

			return nil
		},
	})
}

package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSPubliclyAccessibleResource See https://github.com/tfsec/tfsec#included-checks for check info
const AWSPubliclyAccessibleResource scanner.RuleID = "AWS011"
const AWSPubliclyAccessibleResourceDescription scanner.RuleDescription = "A resource is marked as publicly accessible."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSPubliclyAccessibleResource,
		Description:    AWSPubliclyAccessibleResourceDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_instance", "aws_dms_replication_instance", "aws_rds_cluster_instance", "aws_redshift_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if publicAttr := block.GetAttribute("publicly_accessible"); publicAttr != nil && publicAttr.Type() == cty.Bool {
				if publicAttr.Value().True() {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' is exposed publicly.", block.Name()),
							publicAttr.Range(),
							publicAttr,
							scanner.SeverityWarning,
						),
					}
				}
			}

			return nil
		},
	})
}

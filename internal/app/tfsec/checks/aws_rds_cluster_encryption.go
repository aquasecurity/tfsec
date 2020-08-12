package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSRdsClusterEncryptionNotEnabled See https://github.com/liamg/tfsec#included-checks for check info
const AWSRdsClusterEncryptionNotEnabled scanner.RuleID = "AWS026"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSRdsClusterEncryptionNotEnabled,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_rds_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			rdsClusterEncryptionStatusAttr := block.GetAttribute("kms_key_id")

			if rdsClusterEncryptionStatusAttr == nil  {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a disabled RDS Aurora Cluster encryption.", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if rdsClusterEncryptionStatusAttr.Type() == cty.Bool && rdsClusterEncryptionStatusAttr.Value().False() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines a disabled RDS Aurora Cluster encryption.", block.Name()),
						rdsClusterEncryptionStatusAttr.Range(),
						rdsClusterEncryptionStatusAttr,
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}
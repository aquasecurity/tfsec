package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSRdsClusterPerformanceInsightsEncryptionNotEnabled See https://github.com/liamg/tfsec#included-checks for check info
const AWSRdsClusterPerformanceInsightsEncryptionNotEnabled scanner.RuleID = "AWS028"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSRdsClusterPerformanceInsightsEncryptionNotEnabled,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_rds_cluster_instance"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			rdsClusterPerformanceInsightsEnabledAttr := block.GetAttribute("performance_insights_enabled")
			rdsClusterPerformanceInsightsEncryptionStatusAttr := block.GetAttribute("performance_insights_kms_key_id")

			if rdsClusterPerformanceInsightsEnabledAttr != nil {

			if rdsClusterPerformanceInsightsEncryptionStatusAttr == nil  {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a disabled RDS Aurora Cluster Performance Insights Encryption.", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if rdsClusterPerformanceInsightsEncryptionStatusAttr.Type() == cty.Bool && rdsClusterPerformanceInsightsEncryptionStatusAttr.Value().False() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines a disabled RDS Aurora Cluster Performance Insights Encryption.", block.Name()),
						rdsClusterPerformanceInsightsEncryptionStatusAttr.Range(),
						rdsClusterPerformanceInsightsEncryptionStatusAttr,
						scanner.SeverityError,
					),
				}
			}
			}
			return nil
		},
	})
}
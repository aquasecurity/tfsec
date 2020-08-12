package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSRdsPerformanceInsightsEncryptionNotEnabled See https://github.com/liamg/tfsec#included-checks for check info
const AWSRdsPerformanceInsightsEncryptionNotEnabled scanner.RuleID = "AWS029"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSRdsPerformanceInsightsEncryptionNotEnabled,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_instance"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			rdsPerformanceInsightsEnabledAttr := block.GetAttribute("performance_insights_enabled")
			rdsPerformanceInsightsEncryptionStatusAttr := block.GetAttribute("performance_insights_kms_key_id")

			if rdsPerformanceInsightsEnabledAttr != nil {

			if rdsPerformanceInsightsEncryptionStatusAttr == nil  {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a disabled RDS Instance Performance Insights Encryption.", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if rdsPerformanceInsightsEncryptionStatusAttr.Type() == cty.Bool && rdsPerformanceInsightsEncryptionStatusAttr.Value().False() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines a disabled RDS Instance Performance Insights Encryption.", block.Name()),
						rdsPerformanceInsightsEncryptionStatusAttr.Range(),
						rdsPerformanceInsightsEncryptionStatusAttr,
						scanner.SeverityError,
					),
				}
			}
			}
			return nil
		},
	})
}
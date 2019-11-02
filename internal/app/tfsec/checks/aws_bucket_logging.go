package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSNoBucketLogging See https://github.com/liamg/tfsec#included-checks for check info
const AWSNoBucketLogging scanner.CheckCode = "AWS002"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSNoBucketLogging,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(check *scanner.Check, block *parser.Block) []scanner.Result {
			if loggingBlock := block.GetBlock("logging"); loggingBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have logging enabled.", block.Name()),
						block.Range(),
					),
				}
			}
			return nil
		},
	})
}

package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSNoBucketLogging See https://github.com/liamg/tfsec#included-checks for check info
const AWSNoBucketLogging Code = "AWS002"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(block *parser.Block) []Result {
			if loggingBlock := block.GetBlock("logging"); loggingBlock == nil {
				return []Result{
					NewResult(
						AWSNoBucketLogging,
						fmt.Sprintf("Resource '%s' does not have logging enabled.", block.Name()),
						block.Range(),
					),
				}
			}
			return nil
		},
	})
}

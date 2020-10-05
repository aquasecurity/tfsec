package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSNoBucketLogging See https://github.com/tfsec/tfsec#included-checks for check info
const AWSNoBucketLogging scanner.RuleID = "AWS002"
const AWSNoBucketLoggingDescription scanner.RuleDescription = "S3 Bucket does not have logging enabled."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSNoBucketLogging,
		Description:    AWSNoBucketLoggingDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if loggingBlock := block.GetBlock("logging"); loggingBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have logging enabled.", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}

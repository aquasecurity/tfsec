package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

// AWSNoBucketLogging See https://github.com/liamg/tfsec#included-checks for check info
const AWSNoBucketLogging Code = "AWS002"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {
			if _, exists := getBlock(block, "logging"); !exists {
				return []Result{
					NewResult(
						AWSNoBucketLogging,
						fmt.Sprintf("Resource '%s' does not have logging enabled.", getBlockName(block)),
						nil,
					),
				}
			}
			return nil
		},
	})
}

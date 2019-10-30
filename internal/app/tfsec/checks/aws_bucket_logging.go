package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

const AWSNoBucketLogging Code = "AWS002"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {
			if _, _, exists := getAttribute(block, ctx, "logging"); !exists {
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

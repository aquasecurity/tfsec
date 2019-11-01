package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSBadBucketACL See https://github.com/liamg/tfsec#included-checks for check info
const AWSBadBucketACL Code = "AWS001"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(block *parser.Block) []Result {
			if attr := block.GetAttribute("acl"); attr != nil && attr.Value().Type() == cty.String {
				acl := attr.Value().AsString()
				if acl == "public-read" || acl == "public-read-write" || acl == "website" {
					return []Result{
						NewResult(
							AWSBadBucketACL,
							fmt.Sprintf("Resource '%s' has an ACL which allows public read access.", block.Name()),
							attr.Range(),
						),
					}
				}
			}
			return nil
		},
	})
}

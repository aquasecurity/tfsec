package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSBadBucketACL See https://github.com/tfsec/tfsec#included-checks for check info
const AWSBadBucketACL scanner.RuleID = "AWS001"
const AwsBadBucketACLDescription scanner.RuleDescription = "S3 Bucket has an ACL defined which allows public access."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSBadBucketACL,
		Description:    AwsBadBucketACLDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if attr := block.GetAttribute("acl"); attr != nil && attr.Value().Type() == cty.String {
				acl := attr.Value().AsString()
				if acl == "public-read" || acl == "public-read-write" || acl == "website" {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' has an ACL which allows public read access.", block.Name()),
							attr.Range(),
							attr,
							scanner.SeverityWarning,
						),
					}
				}
			}
			return nil
		},
	})
}

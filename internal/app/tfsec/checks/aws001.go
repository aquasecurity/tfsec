package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSBadBucketACL scanner.RuleCode = "AWS001"
const AwsBadBucketACLDescription scanner.RuleSummary = "S3 Bucket has an ACL defined which allows public access."
const AWSBadBucketACLExplanation = `
S3 bucket permissions should be set to deny public access unless explicitly required.

Granting write access publicly with <code>public-read-write</code> is especially dangerous as you will be billed for any uploaded files.

Additionally, you should not use the <code>authenticated-read</code> canned ACL, as this provides read access to any authenticated AWS user, not just AWS users within your organisation.
`
const AWSBadBucketACLBadExample = `
resource "aws_s3_bucket" "bad_example" {
	acl = "public-read"
}
`
const AWSBadBucketACLGoodExample = `
resource "aws_s3_bucket" "good_example" {
	acl = "private"
}
`
const AWSBadBucketACLImpact = "The contents of the bucket can be accessed publicly"

const AWSBadBucketACLResolution = "Apply a more restrictive bucket ACL"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSBadBucketACL,
		Documentation: scanner.CheckDocumentation{
			Summary:     AwsBadBucketACLDescription,
			Explanation: AWSBadBucketACLExplanation,
			Impact:      AWSBadBucketACLImpact,
			Resolution:  AWSBadBucketACLResolution,
			BadExample:  AWSBadBucketACLBadExample,
			GoodExample: AWSBadBucketACLGoodExample,
			Links: []string{
				"https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if attr := block.GetAttribute("acl"); attr != nil {
				if attr.IsAny("public-read", "public-read-write", "website") {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' has an ACL which allows public access.", block.FullName()),
							attr.Range(),
							attr,
							scanner.SeverityWarning,
						),
					}
				}
				if attr.Equals("authenticated-read") {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' has an ACL which allows access to any authenticated AWS user, not just users within the target account.", block.FullName()),
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

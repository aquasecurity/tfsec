package aws

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// AWSBadBucketACL See https://github.com/tfsec/tfsec#included-checks for check info
const AWSBadBucketACL scanner.RuleID = "AWS001"
const AwsBadBucketACLDescription scanner.RuleSummary = "S3 Bucket has an ACL defined which allows public access."
const AWSBadBucketACLExplanation = `
S3 bucket permissions should be set to deny public access unless explicitly required.

Granting write access publicly with ` + "`" + `public-read-write` + "`" + ` is especially dangerous as you will be billed for any uploaded files.

Additionally, you should not use the 'authenticated-read' canned ACL, as this provides read access to any authenticated AWS user, not just AWS users within your organisation.
`
const AWSBadBucketACLBadExample = `
resource "aws_s3_bucket" "my-bucket" {
	acl = "public-read"
}
`
const AWSBadBucketACLGoodExample = `
resource "aws_s3_bucket" "my-bucket" {
	acl = "private"
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSBadBucketACL,
		Documentation: scanner.CheckDocumentation{
			Summary:     AwsBadBucketACLDescription,
			Explanation: AWSBadBucketACLExplanation,
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
			if attr := block.GetAttribute("acl"); attr != nil && attr.Value().Type() == cty.String {
				acl := attr.Value().AsString()
				if acl == "public-read" || acl == "public-read-write" || acl == "website" {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' has an ACL which allows public access.", block.Name()),
							attr.Range(),
							attr,
							scanner.SeverityWarning,
						),
					}
				}
				if acl == "authenticated-read" {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' has an ACL which allows access to any authenticated AWS user, not just users within the target account.", block.Name()),
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

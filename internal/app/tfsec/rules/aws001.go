package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSBadBucketACL = "AWS001"
const AWSBadBucketACLDescription = "S3 Bucket has an ACL defined which allows public access."
const AWSBadBucketACLImpact = "The contents of the bucket can be accessed publicly"
const AWSBadBucketACLResolution = "Apply a more restrictive bucket ACL"
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

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSBadBucketACL,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSBadBucketACLDescription,
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
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_s3_bucket"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			if attr := resourceBlock.GetAttribute("acl"); attr != nil {
				if attr.IsAny("public-read", "public-read-write", "website") {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' has an ACL which allows public access.", resourceBlock.FullName())).
							WithAttributeAnnotation(attr).
							WithRange(attr.Range()),
					)
				} else if attr.Equals("authenticated-read") {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' has an ACL which allows access to any authenticated AWS user, not just users within the target account.", resourceBlock.FullName())).
							WithRange(attr.Range()),
					)
				}
			}
		},
	})
}

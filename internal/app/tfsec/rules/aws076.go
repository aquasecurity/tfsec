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

const AWSBlockPublicPolicyS3 = "AWS076"
const AWSBlockPublicPolicyS3Description = "S3 Access block should block public policy"
const AWSBlockPublicPolicyS3Impact = "Users could put a policy that allows public access"
const AWSBlockPublicPolicyS3Resolution = "Prevent policies that allow public access being PUT"
const AWSBlockPublicPolicyS3Explanation = `
S3 bucket policy should have block public policy to prevent users from putting a policy that enable public access.
`
const AWSBlockPublicPolicyS3BadExample = `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
  
	block_public_policy = false
}
`
const AWSBlockPublicPolicyS3GoodExample = `
resource "aws_s3_bucket_public_access_block" "good_example" {
	bucket = aws_s3_bucket.example.id
  
	block_public_policy = true
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSBlockPublicPolicyS3,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSBlockPublicPolicyS3Description,
			Impact:      AWSBlockPublicPolicyS3Impact,
			Resolution:  AWSBlockPublicPolicyS3Resolution,
			Explanation: AWSBlockPublicPolicyS3Explanation,
			BadExample:  AWSBlockPublicPolicyS3BadExample,
			GoodExample: AWSBlockPublicPolicyS3GoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#block_public_policy",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_s3_bucket_public_access_block"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			if resourceBlock.MissingChild("block_public_policy") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not specify block_public_policy, defaults to false", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			attr := resourceBlock.GetAttribute("block_public_policy")
			if attr.IsFalse() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' sets block_public_policy explicitly to false", resourceBlock.FullName())).
						WithRange(attr.Range()).
						WithAttributeAnnotation(attr),
				)
			}
		},
	})
}

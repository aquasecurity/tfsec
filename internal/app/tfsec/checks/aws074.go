package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSBlockPublicAclS3 scanner.RuleCode = "AWS074"
const AWSBlockPublicAclS3Description scanner.RuleSummary = "S3 Access block should block public ACL"
const AWSBlockPublicAclS3Explanation = `
S3 buckets should block public ACLs on buckets and any objects they contain. By blocking, PUTs with fail if the object has any public ACL a.
`
const AWSBlockPublicAclS3BadExample = `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
  
	block_public_acls = false
}
`
const AWSBlockPublicAclS3GoodExample = `
resource "aws_s3_bucket_public_access_block" "good_example" {
	bucket = aws_s3_bucket.example.id
  
	block_public_acls = true
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSBlockPublicAclS3,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSBlockPublicAclS3Description,
			Explanation: AWSBlockPublicAclS3Explanation,
			BadExample:  AWSBlockPublicAclS3BadExample,
			GoodExample: AWSBlockPublicAclS3GoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#block_public_acls",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket_public_access_block"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if block.MissingChild("block_public_acls") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not specify block_public_acls, defaults to false", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			attr := block.GetAttribute("block_public_acls")
			if attr.IsFalse() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' sets block_public_acls explicitly to false", block.FullName()),
						attr.Range(),
						attr,
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}

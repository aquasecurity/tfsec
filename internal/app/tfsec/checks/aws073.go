package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSIngorePublicAclS3 scanner.RuleCode = "AWS073"
const AWSIngorePublicAclS3Description scanner.RuleSummary = "S3 Access Block should Ignore Public Acl"
const AWSIngorePublicAclS3Impact = "PUT calls with public ACLs specified can make objects public"
const AWSIngorePublicAclS3Resolution = "Enable ignoring the application of public ACLs in PUT calls"
const AWSIngorePublicAclS3Explanation = `
S3 buckets should ignore public ACLs on buckets and any objects they contain. By ignoring rather than blocking, PUT calls with public ACLs will still be applied but the ACL will be ignored.
`
const AWSIngorePublicAclS3BadExample = `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
  
	ignore_public_acls = false
}
`
const AWSIngorePublicAclS3GoodExample = `
resource "aws_s3_bucket_public_access_block" "good_example" {
	bucket = aws_s3_bucket.example.id
  
	ignore_public_acls = true
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSIngorePublicAclS3,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSIngorePublicAclS3Description,
			Impact:      AWSIngorePublicAclS3Impact,
			Resolution:  AWSIngorePublicAclS3Resolution,
			Explanation: AWSIngorePublicAclS3Explanation,
			BadExample:  AWSIngorePublicAclS3BadExample,
			GoodExample: AWSIngorePublicAclS3GoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#ignore_public_acls",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket_public_access_block"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("ignore_public_acls") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not specify ignore_public_acls, defaults to false", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			attr := block.GetAttribute("ignore_public_acls")
			if attr.IsFalse() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' sets ignore_public_acls explicitly to false", block.FullName()),
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

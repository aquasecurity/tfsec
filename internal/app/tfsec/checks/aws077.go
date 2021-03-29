package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSS3DataShouldBeVersioned scanner.RuleCode = "AWS077"
const AWSS3DataShouldBeVersionedDescription scanner.RuleSummary = "S3 Data should be versioned"
const AWSS3DataShouldBeVersionedExplanation = `
Versioning in Amazon S3 is a means of keeping multiple variants of an object in the same bucket. 
You can use the S3 Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets. 
With versioning you can recover more easily from both unintended user actions and application failures.
`
const AWSS3DataShouldBeVersionedBadExample = `
resource "aws_s3_bucket" "bad_example" {

}
`
const AWSS3DataShouldBeVersionedGoodExample = `
resource "aws_s3_bucket" "good_example" {

	versioning {
		enabled = true
	}
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSS3DataShouldBeVersioned,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSS3DataShouldBeVersionedDescription,
			Explanation: AWSS3DataShouldBeVersionedExplanation,
			BadExample:  AWSS3DataShouldBeVersionedBadExample,
			GoodExample: AWSS3DataShouldBeVersionedGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#versioning",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("versioning") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have versioning enabled", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			versioningBlock := block.GetBlock("versioning")
			if versioningBlock.HasChild("enabled") && versioningBlock.GetAttribute("enabled").IsFalse() {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' has versioning block but is disabled", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}

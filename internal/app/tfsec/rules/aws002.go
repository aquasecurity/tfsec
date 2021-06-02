package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSNoBucketLogging = "AWS002"
const AWSNoBucketLoggingDescription = "S3 Bucket does not have logging enabled."
const AWSNoBucketLoggingImpact = "There is no way to determine the access to this bucket"
const AWSNoBucketLoggingResolution = "Add a logging block to the resource to enable access logging"
const AWSNoBucketLoggingExplanation = `
Buckets should have logging enabled so that access can be audited. 
`
const AWSNoBucketLoggingBadExample = `
resource "aws_s3_bucket" "bad_example" {

}
`
const AWSNoBucketLoggingGoodExample = `
resource "aws_s3_bucket" "good_example" {
	logging {
		target_bucket = "target-bucket"
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSNoBucketLogging,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSNoBucketLoggingDescription,
			Explanation: AWSNoBucketLoggingExplanation,
			Impact:      AWSNoBucketLoggingImpact,
			Resolution:  AWSNoBucketLoggingResolution,
			BadExample:  AWSNoBucketLoggingBadExample,
			GoodExample: AWSNoBucketLoggingGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket",
			},
		},
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {
			if loggingBlock := block.GetBlock("logging"); loggingBlock == nil {
				if block.GetAttribute("acl") != nil && block.GetAttribute("acl").Equals("log-delivery-write") {
					return
				}
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' does not have logging enabled.", block.FullName()),
					).WithRange(block.Range()).WithSeverity(severity.Error),
				)
			}
		},
	})
}

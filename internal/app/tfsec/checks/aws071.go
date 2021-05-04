package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSCloudfrontDistributionAccessLoggingEnabled scanner.RuleCode = "AWS071"
const AWSCloudfrontDistributionAccessLoggingEnabledDescription scanner.RuleSummary = "Cloudfront distribution should have Access Logging configured"
const AWSCloudfrontDistributionAccessLoggingEnabledImpact = "Logging provides vital information about access and usage"
const AWSCloudfrontDistributionAccessLoggingEnabledResolution = "Enable logging for CloudFront distributions"
const AWSCloudfrontDistributionAccessLoggingEnabledExplanation = `
You should configure CloudFront Access Logging to create log files that contain detailed information about every user request that CloudFront receives
`
const AWSCloudfrontDistributionAccessLoggingEnabledBadExample = `
resource "aws_cloudfront_distribution" "bad_example" {
	// other config
	// no logging_config
}
`
const AWSCloudfrontDistributionAccessLoggingEnabledGoodExample = `
resource "aws_cloudfront_distribution" "good_example" {
	// other config
	logging_config {
		include_cookies = false
		bucket          = "mylogs.s3.amazonaws.com"
		prefix          = "myprefix"
	}
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSCloudfrontDistributionAccessLoggingEnabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSCloudfrontDistributionAccessLoggingEnabledDescription,
			Impact:      AWSCloudfrontDistributionAccessLoggingEnabledImpact,
			Resolution:  AWSCloudfrontDistributionAccessLoggingEnabledResolution,
			Explanation: AWSCloudfrontDistributionAccessLoggingEnabledExplanation,
			BadExample:  AWSCloudfrontDistributionAccessLoggingEnabledBadExample,
			GoodExample: AWSCloudfrontDistributionAccessLoggingEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#logging_config",
				"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudfront_distribution"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("logging_config") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have Access Logging configured", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}

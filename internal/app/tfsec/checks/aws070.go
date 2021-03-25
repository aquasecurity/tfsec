package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSCloudfrontDistributionAccessLoggingEnabled scanner.RuleCode = "AWS070"
const AWSCloudfrontDistributionAccessLoggingEnabledDescription scanner.RuleSummary = "Cloudfront distribution should have Access Logging configured"
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
			Explanation: AWSCloudfrontDistributionAccessLoggingEnabledExplanation,
			BadExample:  AWSCloudfrontDistributionAccessLoggingEnabledBadExample,
			GoodExample: AWSCloudfrontDistributionAccessLoggingEnabledGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudfront_distribution"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			loggingConfigBlock := block.GetBlock("logging_config")
			if loggingConfigBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Cloudfront distribution '%s' does not have Access Logging configured", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}

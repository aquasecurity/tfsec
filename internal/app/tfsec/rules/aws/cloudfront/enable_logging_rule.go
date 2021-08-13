package cloudfront

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS071",
		Service:   "cloudfront",
		ShortCode: "enable-logging",
		Documentation: rule.RuleDocumentation{
			Summary:    "Cloudfront distribution should have Access Logging configured",
			Impact:     "Logging provides vital information about access and usage",
			Resolution: "Enable logging for CloudFront distributions",
			Explanation: `
You should configure CloudFront Access Logging to create log files that contain detailed information about every user request that CloudFront receives
`,
			BadExample: []string{`
resource "aws_cloudfront_distribution" "bad_example" {
	// other config
	// no logging_config
}
`},
			GoodExample: []string{`
resource "aws_cloudfront_distribution" "good_example" {
	// other config
	logging_config {
		include_cookies = false
		bucket          = "mylogs.s3.amazonaws.com"
		prefix          = "myprefix"
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#logging_config",
				"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_cloudfront_distribution"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("logging_config") {
				set.AddResult().
					WithDescription("Resource '%s' does not have Access Logging configured", resourceBlock.FullName())
			}

		},
	})
}

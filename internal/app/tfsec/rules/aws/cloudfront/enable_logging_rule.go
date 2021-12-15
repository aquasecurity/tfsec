package cloudfront

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/cloudfront"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS071",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudfront_distribution"},
		Base:           cloudfront.CheckEnableLogging,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if resourceBlock.MissingChild("logging_config") {
				results.Add("Resource does not have Access Logging configured", resourceBlock)
			}
			return results
		},
	})
}

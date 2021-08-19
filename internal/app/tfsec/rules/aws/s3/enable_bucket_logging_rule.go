package s3

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/defsec/rules/aws/s3"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS002",
		Service:   "s3",
		ShortCode: "enable-bucket-logging",
		Documentation: rule.RuleDocumentation{
			Summary: "S3 Bucket does not have logging enabled.",
			Explanation: `
Buckets should have logging enabled so that access can be audited. 
`,
			Impact:     "There is no way to determine the access to this bucket",
			Resolution: "Add a logging block to the resource to enable access logging",
			BadExample: []string{`
resource "aws_s3_bucket" "bad_example" {

}
`},
			GoodExample: []string{`
resource "aws_s3_bucket" "good_example" {
	logging {
		target_bucket = "target-bucket"
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket",
				"https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html",
			},
		},
		Provider:            provider.AWSProvider,
		RequiredTypes:       []string{"resource"},
		RequiredLabels:      []string{"aws_s3_bucket"},
		DefaultSeverity:     severity.Medium,
		CheckInfrastructure: s3.CheckLoggingIsEnabled,
	})
}

package s3

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules/aws/s3"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS002",
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
		DefSecCheck: s3.CheckLoggingIsEnabled,
	})
}

package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSCloudWatchLogGroupsCMKEncrypted scanner.RuleCode = "AWS089"
const AWSCloudWatchLogGroupsCMKEncryptedDescription scanner.RuleSummary = "CloudWatch log groups should be encrypted using CMK"
const AWSCloudWatchLogGroupsCMKEncryptedImpact = "Log data may be leaked if the logs are compromised. No auditing of who have viewed the logs."
const AWSCloudWatchLogGroupsCMKEncryptedResolution = "Enable CMK encryption of CloudWatch Log Groups"
const AWSCloudWatchLogGroupsCMKEncryptedExplanation = `
CloudWatch log groups are encrypted by default, however, to get the full benefit of controlling key rotation and other KMS aspects a KMS CMK should be used.
`
const AWSCloudWatchLogGroupsCMKEncryptedBadExample = `
resource "aws_cloudwatch_log_group" "bad_exampe" {
	name = "bad_example"

}
`
const AWSCloudWatchLogGroupsCMKEncryptedGoodExample = `
resource "aws_cloudwatch_log_group" "good_example" {
	name = "good_example"

	kms_key_id = aws_kms_key.log_key.id
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSCloudWatchLogGroupsCMKEncrypted,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSCloudWatchLogGroupsCMKEncryptedDescription,
			Explanation: AWSCloudWatchLogGroupsCMKEncryptedExplanation,
			Impact:      AWSCloudWatchLogGroupsCMKEncryptedImpact,
			Resolution:  AWSCloudWatchLogGroupsCMKEncryptedResolution,
			BadExample:  AWSCloudWatchLogGroupsCMKEncryptedBadExample,
			GoodExample: AWSCloudWatchLogGroupsCMKEncryptedGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group#kms_key_id",
				"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudwatch_log_group"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if block.MissingChild("kms_key_id") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' is only using default encryption", block.FullName()),
						block.Range(),
						scanner.SeverityInfo,
					),
				}
			}

			return nil
		},
	})
}

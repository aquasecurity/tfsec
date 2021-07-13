package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSCloudWatchLogGroupsCMKEncrypted = "AWS089"
const AWSCloudWatchLogGroupsCMKEncryptedDescription = "CloudWatch log groups should be encrypted using CMK"
const AWSCloudWatchLogGroupsCMKEncryptedImpact = "Log data may be leaked if the logs are compromised. No auditing of who have viewed the logs."
const AWSCloudWatchLogGroupsCMKEncryptedResolution = "Enable CMK encryption of CloudWatch Log Groups"
const AWSCloudWatchLogGroupsCMKEncryptedExplanation = `
CloudWatch log groups are encrypted by default, however, to get the full benefit of controlling key rotation and other KMS aspects a KMS CMK should be used.
`
const AWSCloudWatchLogGroupsCMKEncryptedBadExample = `
resource "aws_cloudwatch_log_group" "bad_example" {
	name = "bad_example"

}
`
const AWSCloudWatchLogGroupsCMKEncryptedGoodExample = `
resource "aws_cloudwatch_log_group" "good_example" {
	name = "good_example"

	kms_key_id = aws_kms_key.log_key.arn
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSCloudWatchLogGroupsCMKEncrypted,
		Documentation: rule.RuleDocumentation{
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
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_cloudwatch_log_group"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			if resourceBlock.MissingChild("kms_key_id") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' is only using default encryption", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			}

		},
	})
}

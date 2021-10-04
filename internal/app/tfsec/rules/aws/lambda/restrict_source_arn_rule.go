package lambda

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
		LegacyID:  "AWS058",
		Service:   "lambda",
		ShortCode: "restrict-source-arn",
		Documentation: rule.RuleDocumentation{
			Summary:    "Ensure that lambda function permission has a source arn specified",
			Impact:     "Not providing the source ARN allows any resource from principal, even from other accounts",
			Resolution: "Always provide a source arn for Lambda permissions",
			Explanation: `When the principal is an AWS service, the ARN of the specific resource within that service to grant permission to. 

Without this, any resource from principal will be granted permission – even if that resource is from another account. 

For S3, this should be the ARN of the S3 Bucket. For CloudWatch Events, this should be the ARN of the CloudWatch Events Rule. For API Gateway, this should be the ARN of the API`,
			BadExample: []string{`
resource "aws_lambda_permission" "bad_example" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.func.function_name
  principal     = "sns.amazonaws.com"
}
`},
			GoodExample: []string{`
resource "aws_lambda_permission" "good_example" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.func.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.default.arn
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission",
				"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_lambda_permission"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.HasChild("principal") {
				if resourceBlock.GetAttribute("principal").EndsWith("amazonaws.com") {
					if resourceBlock.MissingChild("source_arn") {
						set.AddResult().
							WithDescription("Resource '%s' missing source ARN but has *.amazonaws.com Principal.", resourceBlock.FullName())
					}
				}
			}

		},
	})
}

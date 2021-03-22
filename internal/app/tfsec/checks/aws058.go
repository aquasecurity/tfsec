package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSCheckLambdaFunctionForSourceARN scanner.RuleCode = "AWS058"
const AWSCheckLambdaFunctionForSourceARNDescription scanner.RuleSummary = "Ensure that lambda function permission has a source arn specified"
const AWSCheckLambdaFunctionForSourceARNExplanation = `When the principal is an AWS service, the ARN of the specific resource within that service to grant permission to. 

Without this, any resource from principal will be granted permission – even if that resource is from another account. 

For S3, this should be the ARN of the S3 Bucket. For CloudWatch Events, this should be the ARN of the CloudWatch Events Rule. For API Gateway, this should be the ARN of the API`
const AWSCheckLambdaFunctionForSourceARNBadExample = `
resource "aws_lambda_permission" "bad_example" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.func.function_name
  principal     = "sns.amazonaws.com"
}
`
const AWSCheckLambdaFunctionForSourceARNGoodExample = `
resource "aws_lambda_permission" "good_example" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.func.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.default.arn
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSCheckLambdaFunctionForSourceARN,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSCheckLambdaFunctionForSourceARNDescription,
			Explanation: AWSCheckLambdaFunctionForSourceARNExplanation,
			BadExample:  AWSCheckLambdaFunctionForSourceARNBadExample,
			GoodExample: AWSCheckLambdaFunctionForSourceARNGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission",
				"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_lambda_permission"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.HasChild("principal") {
				if block.GetAttribute("principal").EndsWith("amazonaws.com") {
					if block.MissingChild("source_arn") {
						return []scanner.Result{
							check.NewResult(
								fmt.Sprintf("Resource '%s' missing source ARN but has *.amazonaws.com Principal.", block.FullName()),
								block.Range(),
								scanner.SeverityError,
							),
						}
					}
				}
			}

			return nil
		},
	})
}

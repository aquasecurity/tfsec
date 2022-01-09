package lambda

import (
	"github.com/aquasecurity/defsec/rules/aws/lambda"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS058",
		BadExample: []string{`
resource "aws_lambda_permission" "bad_example" {
	statement_id = "AllowExecutionFromSNS"
	action = "lambda:InvokeFunction"
	function_name = aws_lambda_function.func.function_name
	principal = "sns.amazonaws.com"
}
		`},
		GoodExample: []string{`
resource "aws_lambda_permission" "good_example" {
	statement_id = "AllowExecutionFromSNS"
	action = "lambda:InvokeFunction"
	function_name = aws_lambda_function.func.function_name
	principal = "sns.amazonaws.com"
	source_arn = aws_sns_topic.default.arn
}
		`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_lambda_permission"},
		Base:           lambda.CheckRestrictSourceArn,
	})
}

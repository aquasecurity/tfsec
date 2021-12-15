package lambda

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/lambda"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_lambda_permission"},
		Base:           lambda.CheckRestrictSourceArn,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.HasChild("principal") {
				if principalAttr := resourceBlock.GetAttribute("principal"); principalAttr.EndsWith("amazonaws.com") {
					if resourceBlock.MissingChild("source_arn") {
						results.Add("Resource missing source ARN but has *.amazonaws.com principal.", principalAttr)
					}
				}
			}

			return results
		},
	})
}

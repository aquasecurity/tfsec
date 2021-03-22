package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSAPIGatewayHasAccessLoggingEnabled scanner.RuleCode = "AWS061"
const AWSAPIGatewayHasAccessLoggingEnabledDescription scanner.RuleSummary = "API Gateway stages for V1 and V2 should have access logging enabled"
const AWSAPIGatewayHasAccessLoggingEnabledExplanation = `
API Gateway stages should have access log settings block configured to track all access to a particular stage. This should be applied to both v1 and v2 gateway stages.
`
const AWSAPIGatewayHasAccessLoggingEnabledBadExample = `
resource "aws_apigatewayv2_stage" "bad_example" {
  api_id = aws_apigatewayv2_api.example.id
  name   = "example-stage"
}

resource "aws_api_gateway_stage" "bad_example" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "example"
}
`
const AWSAPIGatewayHasAccessLoggingEnabledGoodExample = `
resource "aws_apigatewayv2_stage" "good_example" {
  api_id = aws_apigatewayv2_api.example.id
  name   = "example-stage"

  access_log_settings {
    destination_arn = ""
    format          = ""
  }
}

resource "aws_api_gateway_stage" "good_example" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "example"

  access_log_settings {
    destination_arn = ""
    format          = ""
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSAPIGatewayHasAccessLoggingEnabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSAPIGatewayHasAccessLoggingEnabledDescription,
			Explanation: AWSAPIGatewayHasAccessLoggingEnabledExplanation,
			BadExample:  AWSAPIGatewayHasAccessLoggingEnabledBadExample,
			GoodExample: AWSAPIGatewayHasAccessLoggingEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/apigatewayv2_stage#access_log_settings",
				"https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_apigatewayv2_stage", "aws_api_gateway_stage"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("access_log_settings") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' is missing access log settings block.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}

package apigateway

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
		LegacyID:  "AWS061",
		Service:   "api-gateway",
		ShortCode: "enable-access-logging",
		Documentation: rule.RuleDocumentation{
			Summary:    "API Gateway stages for V1 and V2 should have access logging enabled",
			Impact:     "Logging provides vital information about access and usage",
			Resolution: "Enable logging for API Gateway stages",
			Explanation: `
API Gateway stages should have access log settings block configured to track all access to a particular stage. This should be applied to both v1 and v2 gateway stages.
`,
			BadExample: []string{`
resource "aws_apigatewayv2_stage" "bad_example" {
  api_id = aws_apigatewayv2_api.example.id
  name   = "example-stage"
}

resource "aws_api_gateway_stage" "bad_example" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "example"
}
`},
			GoodExample: []string{`
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
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/apigatewayv2_stage#access_log_settings",
				"https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_apigatewayv2_stage", "aws_api_gateway_stage"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("access_log_settings") {
				set.AddResult().
					WithDescription("Resource '%s' is missing access log settings block.", resourceBlock.FullName())
			}
		},
	})
}

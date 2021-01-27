package checks

import (
	"encoding/json"
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/security"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSTaskDefinitionWithSensitiveEnvironmentVariables scanner.RuleCode = "AWS013"
const AWSTaskDefinitionWithSensitiveEnvironmentVariablesDescription scanner.RuleSummary = "Task definition defines sensitive environment variable(s)."
const AWSTaskDefinitionWithSensitiveEnvironmentVariablesExplanation = `
You should not make secrets available to a user in plaintext in any scenario. Secrets can instead be pulled from a secure secret storage system by the service requiring them.  
`
const AWSTaskDefinitionWithSensitiveEnvironmentVariablesBadExample = `
resource "aws_ecs_task_definition" "my-task" {
  container_definitions = <<EOF
[
  {
    "name": "my_service",
    "essential": true,
    "memory": 256,
    "environment": [
      { "name": "ENVIRONMENT", "value": "development" },
      { "name": "DATABASE_PASSWORD", "value": "oh no D:"}
    ]
  }
]
EOF

}
`
const AWSTaskDefinitionWithSensitiveEnvironmentVariablesGoodExample = `
resource "aws_ecs_task_definition" "my-task" {
  container_definitions = <<EOF
[
  {
    "name": "my_service",
    "essential": true,
    "memory": 256,
    "environment": [
      { "name": "ENVIRONMENT", "value": "development" }
    ]
  }
]
EOF

}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSTaskDefinitionWithSensitiveEnvironmentVariables,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSTaskDefinitionWithSensitiveEnvironmentVariablesDescription,
			Explanation: AWSTaskDefinitionWithSensitiveEnvironmentVariablesExplanation,
			BadExample:  AWSTaskDefinitionWithSensitiveEnvironmentVariablesBadExample,
			GoodExample: AWSTaskDefinitionWithSensitiveEnvironmentVariablesGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html",
				"https://www.vaultproject.io/",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecs_task_definition"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			var results []scanner.Result

			if definitionsAttr := block.GetAttribute("container_definitions"); definitionsAttr != nil && definitionsAttr.Type() == cty.String {
				rawJSON := []byte(definitionsAttr.Value().AsString())

				var definitions []struct {
					EnvVars []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"environment"`
				}

				if err := json.Unmarshal(rawJSON, &definitions); err != nil {
					return nil
				}

				for _, definition := range definitions {
					for _, env := range definition.EnvVars {
						if security.IsSensitiveAttribute(env.Name) && env.Value != "" {
							results = append(results, check.NewResultWithValueAnnotation(
								fmt.Sprintf("Resource '%s' includes a potentially sensitive environment variable '%s' in the container definition.", block.FullName(), env.Name),
								definitionsAttr.Range(),
								definitionsAttr,
								scanner.SeverityWarning,
							))
						}
					}
				}

			}

			return results
		},
	})
}

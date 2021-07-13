package rules

import (
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/security"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

const AWSTaskDefinitionWithSensitiveEnvironmentVariables = "AWS013"
const AWSTaskDefinitionWithSensitiveEnvironmentVariablesDescription = "Task definition defines sensitive environment variable(s)."
const AWSTaskDefinitionWithSensitiveEnvironmentVariablesImpact = "Sensitive data could be exposed in the AWS Management Console"
const AWSTaskDefinitionWithSensitiveEnvironmentVariablesResolution = "Use secrets for the task definition"
const AWSTaskDefinitionWithSensitiveEnvironmentVariablesExplanation = `
You should not make secrets available to a user in plaintext in any scenario. Secrets can instead be pulled from a secure secret storage system by the service requiring them.  
`
const AWSTaskDefinitionWithSensitiveEnvironmentVariablesBadExample = `
resource "aws_ecs_task_definition" "bad_example" {
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
resource "aws_ecs_task_definition" "good_example" {
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSTaskDefinitionWithSensitiveEnvironmentVariables,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSTaskDefinitionWithSensitiveEnvironmentVariablesDescription,
			Impact:      AWSTaskDefinitionWithSensitiveEnvironmentVariablesImpact,
			Resolution:  AWSTaskDefinitionWithSensitiveEnvironmentVariablesResolution,
			Explanation: AWSTaskDefinitionWithSensitiveEnvironmentVariablesExplanation,
			BadExample:  AWSTaskDefinitionWithSensitiveEnvironmentVariablesBadExample,
			GoodExample: AWSTaskDefinitionWithSensitiveEnvironmentVariablesGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html",
				"https://www.vaultproject.io/",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_ecs_task_definition"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if definitionsAttr := resourceBlock.GetAttribute("container_definitions"); definitionsAttr != nil && definitionsAttr.Type() == cty.String {
				rawJSON := []byte(definitionsAttr.Value().AsString())

				var definitions []struct {
					EnvVars []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"environment"`
				}

				if err := json.Unmarshal(rawJSON, &definitions); err != nil {
					debug.Log("an error occurred processing container definition json: %s: %s", resourceBlock.Range(), err.Error())
					return
				}

				for _, definition := range definitions {
					for _, env := range definition.EnvVars {
						if security.IsSensitiveAttribute(env.Name) && env.Value != "" {
							set.Add(result.New(resourceBlock).
								WithDescription(fmt.Sprintf("Resource '%s' includes a potentially sensitive environment variable '%s' in the container definition.", resourceBlock.FullName(), env.Name)).
								WithRange(definitionsAttr.Range()).
								WithAttributeAnnotation(definitionsAttr),
							)
						}
					}
				}

			}

		},
	})
}

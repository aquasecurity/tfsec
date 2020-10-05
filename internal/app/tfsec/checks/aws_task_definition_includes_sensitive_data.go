package checks

import (
	"encoding/json"
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/security"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSTaskDefinitionWithSensitiveEnvironmentVariables See https://github.com/tfsec/tfsec#included-checks for check info
const AWSTaskDefinitionWithSensitiveEnvironmentVariables scanner.RuleID = "AWS013"
const AWSTaskDefinitionWithSensitiveEnvironmentVariablesDescription scanner.RuleDescription = "Task definition defines sensitive environment variable(s)."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSTaskDefinitionWithSensitiveEnvironmentVariables,
		Description:    AWSTaskDefinitionWithSensitiveEnvironmentVariablesDescription,
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
								fmt.Sprintf("Resource '%s' includes a potentially sensitive environment variable '%s' in the container definition.", block.Name(), env.Name),
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

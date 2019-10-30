package checks

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

// AWSTaskDefinitionWithSensitiveEnvironmentVariables See https://github.com/liamg/tfsec#included-checks for check info
const AWSTaskDefinitionWithSensitiveEnvironmentVariables Code = "AWS013"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecs_task_definition"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {

			var results []Result

			if definitionsVal, attrRange, exists := getAttribute(block, ctx, "container_definitions"); exists {
				rawJSON := []byte(definitionsVal.AsString())

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
						if isSensitiveName(env.Name) && env.Value != "" {
							results = append(results, NewResult(
								AWSTaskDefinitionWithSensitiveEnvironmentVariables,
								fmt.Sprintf("Resource '%s' includes a potentially sensitive environment variable '%s' in the container definition.", getBlockName(block), env.Name),
								attrRange,
							))
						}
					}
				}

			}

			return results
		},
	})
}

package ecs

// generator-locked
import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/ecs"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/security"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/zclconf/go-cty/cty"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS013",
		BadExample: []string{`
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
 `},
		GoodExample: []string{`
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
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition",
			"https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html",
			"https://www.vaultproject.io/",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecs_task_definition"},
		Base:           ecs.CheckNoPlaintextSecrets,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if definitionsAttr := resourceBlock.GetAttribute("container_definitions"); definitionsAttr.IsNotNil() && definitionsAttr.Type() == cty.String {
				rawJSON := strings.TrimSpace(definitionsAttr.Value().AsString())

				var definitions []struct {
					EnvVars []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"environment"`
				}

				err := json.Unmarshal([]byte(rawJSON), &definitions)
				if err != nil {
					debug.Log("an error occurred processing container definition json: %s: %s", resourceBlock.Range(), err.Error())
					return
				}

				for _, definition := range definitions {
					for _, env := range definition.EnvVars {
						if security.IsSensitiveAttribute(env.Name) && env.Value != "" {
							results.Add(
								fmt.Sprintf("Resource includes a potentially sensitive environment variable ('%s') in the container definition.", env.Name),
								definitionsAttr,
							)
						}
					}
				}
			}

			return results
		},
	})
}

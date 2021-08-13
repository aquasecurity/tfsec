package ecs

// generator-locked
import (
	"encoding/json"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/security"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS013",
		Service:   "ecs",
		ShortCode: "no-plaintext-secrets",
		Documentation: rule.RuleDocumentation{
			Summary:    "Task definition defines sensitive environment variable(s).",
			Impact:     "Sensitive data could be exposed in the AWS Management Console",
			Resolution: "Use secrets for the task definition",
			Explanation: `
You should not make secrets available to a user in plaintext in any scenario. Secrets can instead be pulled from a secure secret storage system by the service requiring them.  
`,
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
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_ecs_task_definition"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

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
							set.AddResult().WithDescription("Resource '%s' includes a potentially sensitive environment variable '%s' in the container definition.", resourceBlock.FullName(), env.Name).
								WithAttribute(definitionsAttr)
						}
					}
				}

			}

		},
	})
}

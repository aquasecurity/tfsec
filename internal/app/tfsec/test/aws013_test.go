package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSTaskDefinitionIncludesSensitiveData(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check aws_ecs_task_definition when sensitive env vars are included",
			source: `
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

}`,
			mustIncludeResultCode: checks.AWSTaskDefinitionWithSensitiveEnvironmentVariables,
		},
		{
			name: "check aws_ecs_task_definition when sensitive env vars are not included",
			source: `
resource "aws_ecs_task_definition" "my-task" {
  container_definitions = <<EOF
[
  {
    "name": "my_service",
    "essential": true,
    "memory": 256,
    "environment": [
      { "name": "ENVIRONMENT", "value": "development" },
      { "name": "DATABASE_HOST", "value": "localhost"}
    ]
  }
]
EOF

}`,
			mustExcludeResultCode: checks.AWSTaskDefinitionWithSensitiveEnvironmentVariables,
		},
		{
			name: "check aws_ecs_task_definition when sensitive env vars are included but ignored",
			source: `
resource "aws_ecs_task_definition" "my-task" {
  #tfsec:ignore:*
  container_definitions = <<EOF
[
  {
    "name": "my_service",
    "essential": true,
    "memory": 256,
    "environment": [
      { "name": "ENVIRONMENT", "value": "development" },
      { "name": "DATABASE_PASSWORD", "value": "supersecret"}
    ]
  }
]
EOF

}`,
			mustExcludeResultCode: checks.AWSTaskDefinitionWithSensitiveEnvironmentVariables,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

package tfsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AWSTaskDefinitionIncludesSensitiveData(t *testing.T) {

	var tests = []struct {
		name           string
		source         string
		expectsResults bool
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
			expectsResults: true,
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
			expectsResults: false,
		},
		{
			name: "check aws_ecs_task_definition when sensitive env vars are included but ignored",
			source: `
resource "aws_ecs_task_definition" "my-task" {
  #tfsec:ignore
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
			expectsResults: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assert.Equal(t, test.expectsResults, len(results) > 0)
		})
	}

}

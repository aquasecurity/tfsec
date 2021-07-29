package ecs

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSTaskDefinitionIncludesSensitiveData(t *testing.T) {
	expectedCode := "aws-ecs-no-plaintext-secrets"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		// {
		// 	name: "check aws_ecs_task_definition when sensitive env vars are included",
		// 	source: `
		// resource "aws_ecs_task_definition" "my-task" {
		//   container_definitions = <<EOF
		// [
		//   {
		//     "name": "my_service",
		//     "essential": true,
		//     "memory": 256,
		//     "environment": [
		//       { "name": "ENVIRONMENT", "value": "development" },
		//       { "name": "DATABASE_PASSWORD", "value": "oh no D:"}
		//     ]
		//   }
		// ]
		// EOF

		// }`,
		// 	mustIncludeResultCode: expectedCode,
		// },
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
			mustExcludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

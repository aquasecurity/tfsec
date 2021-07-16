package ecs

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSECSClusterContainerInsights(t *testing.T) {
	expectedCode := "aws-ecs-enable-container-insight"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "ECS cluster without container insights fails check",
			source: `
resource "aws_ecs_cluster" "bad_example" {
  	name = "services-cluster"
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "ECS cluster with container insights configured but disabled fails check",
			source: `
resource "aws_ecs_cluster" "bad_example" {
  	name = "services-cluster"

	setting {
		name  = "containerInsights"
		value = "disabled"
	}
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "ECS cluster with settings but no container insights fails check",
			source: `
resource "aws_ecs_cluster" "bad_example" {
  	name = "services-cluster"
  
	  setting {
		name  = "NotContainerInsights"
		value = "enabled"
	  }
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "ECS cluster with container insights enabled passess check",
			source: `
resource "aws_ecs_cluster" "good_example" {
	name = "services-cluster"
  
	setting {
	  name  = "containerInsights"
	  value = "enabled"
	}
}
`,
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

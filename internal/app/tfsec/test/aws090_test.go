package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSECSClusterContainerInsights(t *testing.T) {

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
			mustIncludeResultCode: rules.AWSECSClusterContainerInsights,
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
			mustIncludeResultCode: rules.AWSECSClusterContainerInsights,
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
			mustIncludeResultCode: rules.AWSECSClusterContainerInsights,
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
			mustExcludeResultCode: rules.AWSECSClusterContainerInsights,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

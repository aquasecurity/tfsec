package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSECSClusterContainerInsights(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "ECS cluster without container insights fails check",
			source: `
resource "aws_ecs_cluster" "bad_example" {
  	name = "services-cluster"
}
`,
			mustIncludeResultCode: checks.AWSECSClusterContainerInsights,
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
			mustIncludeResultCode: checks.AWSECSClusterContainerInsights,
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
			mustIncludeResultCode: checks.AWSECSClusterContainerInsights,
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
			mustExcludeResultCode: checks.AWSECSClusterContainerInsights,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

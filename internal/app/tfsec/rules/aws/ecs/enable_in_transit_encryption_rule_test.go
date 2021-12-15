package ecs

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSECSTaskDefinitionEncryptionInTransit(t *testing.T) {
	expectedCode := "aws-ecs-enable-in-transit-encryption"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "ecs definition with efs and in transit encryption not set fails check",
			source: `
 resource "aws_ecs_task_definition" "bad_example" {
 	family                = "service"
 	container_definitions = file("task-definitions/service.json")
   
 	volume {
 	  name = "service-storage"
   
 	  efs_volume_configuration {
 		file_system_id          = aws_efs_file_system.fs.id
 		root_directory          = "/opt/data"
 		authorization_config {
 		  access_point_id = aws_efs_access_point.test.id
 		  iam             = "ENABLED"
 		}
 	  }
 	}
   }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "ecs definition with efs and in transit encryption set to disabled fails check",
			source: `
 resource "aws_ecs_task_definition" "bad_example" {
 	family                = "service"
 	container_definitions = file("task-definitions/service.json")
   
 	volume {
 	  name = "service-storage"
   
 	  efs_volume_configuration {
 		file_system_id          = aws_efs_file_system.fs.id
 		root_directory          = "/opt/data"
 		transit_encryption      = "DISABLED"
 		transit_encryption_port = 2999
 		authorization_config {
 		  access_point_id = aws_efs_access_point.test.id
 		  iam             = "ENABLED"
 		}
 	  }
 	}
   }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "ecs definition with efs and in transit encryption enabled passes",
			source: `
 resource "aws_ecs_task_definition" "good_example" {
 	family                = "service"
 	container_definitions = file("task-definitions/service.json")
   
 	volume {
 	  name = "service-storage"
   
 	  efs_volume_configuration {
 		file_system_id          = aws_efs_file_system.fs.id
 		root_directory          = "/opt/data"
 		transit_encryption      = "ENABLED"
 		transit_encryption_port = 2999
 		authorization_config {
 		  access_point_id = aws_efs_access_point.test.id
 		  iam             = "ENABLED"
 		}
 	  }
 	}
   }
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "ecs definition without efs passes",
			source: `
 resource "aws_ecs_task_definition" "good_example" {
 	family                = "service"
 	container_definitions = file("task-definitions/service.json")
   
 	volume {
 	  name = "service-storage"
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

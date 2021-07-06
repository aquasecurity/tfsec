package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSECRRepoCustomerManagedKeys(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "ECR repo without configured encryption fails checks",
			source: `
resource "aws_ecr_repository" "bad_example" {
	name                 = "bar"
	image_tag_mutability = "MUTABLE"
  
	image_scanning_configuration {
	  scan_on_push = true
	}
  }
`,
			mustIncludeResultCode: rules.AWSECRRepoCustomerManagedKeys,
		},
		{
			name: "ECR repo with configured encryption but wrong type fails checks",
			source: `
resource "aws_ecr_repository" "bad_example" {
	name                 = "bar"
	image_tag_mutability = "MUTABLE"
  
	image_scanning_configuration {
	  scan_on_push = true
	}
  }
`,
			mustIncludeResultCode: rules.AWSECRRepoCustomerManagedKeys,
		},
		{
			name: "ECR Repo with encryption configured to use KMS CMK passes check",
			source: `
resource "aws_kms_key" "ecr_kms" {
	enable_key_rotation = true
}


resource "aws_ecr_repository" "good_example" {
	name                 = "bar"
	image_tag_mutability = "MUTABLE"
  
	image_scanning_configuration {
	  scan_on_push = true
	}

	encryption_configuration {
		encryption_type = "KMS"
		kms_key = aws_kms_key.ecr_kms.key_id
	}
  }
`,
			mustExcludeResultCode: rules.AWSECRRepoCustomerManagedKeys,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSEKSSecretsEncryptionEnabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "Test eks cluster with no encryption block causes check to fail",
			source: `
resource "aws_eks_cluster" "bad_example" {

    name = "bad_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`,
			mustIncludeResultCode: checks.AWSEKSSecretsEncryptionEnabled,
		},
		{
			name: "Test eks cluster with encryption block causes check to fail when no resources",
			source: `
resource "aws_eks_cluster" "bad_example" {
    encryption_config {
        provider {
            key_arn = var.kms_arn
        }
    }

    name = "bad_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`,
			mustIncludeResultCode: checks.AWSEKSSecretsEncryptionEnabled,
		},
		{
			name: "Test eks cluster with secrets no in the resources attribute causes check to fail",
			source: `
resource "aws_eks_cluster" "bad_example" {
    encryption_config {
        resources = [  ]
        provider {
            key_arn = var.kms_arn
        }
    }

    name = "bad_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`,
			mustIncludeResultCode: checks.AWSEKSSecretsEncryptionEnabled,
		},
		{
			name: "Test eks cluster with secrets in the resources attribute but no provider block causes check to fail",
			source: `
resource "aws_eks_cluster" "bad_example" {
    encryption_config {
        resources = [ "secrets" ]
    }

    name = "bad_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`,
			mustIncludeResultCode: checks.AWSEKSSecretsEncryptionEnabled,
		},
		{
			name: "Test eks cluster with secrets in the resources and provider block but no key_arn set causes check to fail",
			source: `
resource "aws_eks_cluster" "bad_example" {
    encryption_config {
        resources = [ "secrets" ]
        provider {
            key_arn = ""
        }
    }

    name = "bad_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`,
			mustIncludeResultCode: checks.AWSEKSSecretsEncryptionEnabled,
		},
		{
			name: "Test correctly configured eks cluster passes check",
			source: `
resource "aws_eks_cluster" "good_example" {
    encryption_config {
        resources = [ "secrets" ]
        provider {
            key_arn = var.kms_arn
        }
    }

    name = "good_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`,
			mustExcludeResultCode: checks.AWSEKSSecretsEncryptionEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

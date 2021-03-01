package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSEKSHasControlPlaneLoggingEnabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "Test eks cluster with no logging configured fails check",
			source: `
resource "aws_eks_cluster" "bad_example" {
    encryption_config {
        resources = [ "secrets" ]
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
			mustIncludeResultCode: checks.AWSEKSHasControlPlaneLoggingEnabled,
		},
		{
			name: "Test EKS cluster with only some cluster logging enabled fails check",
			source: `
resource "aws_eks_cluster" "bad_example" {
    encryption_config {
        resources = [ "secrets" ]
        provider {
            key_arn = var.kms_arn
        }
    }

	enabled_cluster_log_types = ["api", "authenticator", "scheduler", "controllerManager"]

    name = "bad_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`,
			mustIncludeResultCode: checks.AWSEKSHasControlPlaneLoggingEnabled,
		},
		{
			name: "Test eks cluster with all logging enabled passes check",
			source: `
resource "aws_eks_cluster" "good_example" {
    encryption_config {
        resources = [ "secrets" ]
        provider {
            key_arn = var.kms_arn
        }
    }

	enabled_cluster_log_types = ["api", "authenticator", "audit", "scheduler", "controllerManager"]

    name = "good_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`,
			mustExcludeResultCode: checks.AWSEKSHasControlPlaneLoggingEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSEKSClusterPublicAccessDisabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "Test eks cluster without vpc_config defaults to public access fails check",
			source: `
resource "aws_eks_cluster" "bad_example" {
    // other config 

    name = "bad_example_cluster"
    role_arn = var.cluster_arn
}
`,
			mustIncludeResultCode: checks.AWSEKSClusterPublicAccessDisabled,
		},
		{
			name: "Test vpc config with public access fails check",
			source: `
resource "aws_eks_cluster" "bad_example" {
    // other config 

    name = "bad_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = true
        public_access_cidrs = ["10.2.0.0/8"]
    }
}
`,
			mustIncludeResultCode: checks.AWSEKSClusterPublicAccessDisabled,
		},
		{
			name: "Test eks cluster with the public access disabled passes check",
			source: `
resource "aws_eks_cluster" "good_example" {
    // other config 

    name = "good_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
        public_access_cidrs = ["10.2.0.0/8"]
    }
}
`,
			mustExcludeResultCode: checks.AWSEKSClusterPublicAccessDisabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

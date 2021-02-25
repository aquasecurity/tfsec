package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSEKSClusterNotOpenPublicly(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "Test public access cidrs left to default causes check to fail",
			source: `
resource "aws_eks_cluster" "bad_example" {

    name = "bad_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`,
			mustIncludeResultCode: checks.AWSEKSClusterNotOpenPublicly,
		},
		{
			name: "Test public access cidrs actively set to open check to fail",
			source: `
resource "aws_eks_cluster" "bad_example" {

    name = "bad_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
		public_access_cidrs = [ "0.0.0.0/0" ]
    }
}
`,
			mustIncludeResultCode: checks.AWSEKSClusterNotOpenPublicly,
		},
		{
			name: "Test public access cidrs correctly configured passess check",
			source: `
resource "aws_eks_cluster" "good_example" {

    name = "good_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
        public_access_cidrs = ["10.2.0.0/8"]
    }
}
`,
			mustExcludeResultCode: checks.AWSEKSClusterNotOpenPublicly,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

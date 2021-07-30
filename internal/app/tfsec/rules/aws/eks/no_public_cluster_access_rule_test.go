package eks

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSEKSClusterPublicAccessDisabled(t *testing.T) {
	expectedCode := "aws-eks-no-public-cluster-access"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
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
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
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

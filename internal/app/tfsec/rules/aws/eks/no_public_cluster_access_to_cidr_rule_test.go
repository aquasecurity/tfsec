package eks

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSEKSClusterNotOpenPublicly(t *testing.T) {
	expectedCode := "aws-eks-no-public-cluster-access-to-cidr"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Test public access cidrs left to default causes check to pass if public access is disabled",
			source: `
resource "aws_eks_cluster" "good_example" {

    name = "good_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "Test public access cidrs actively set to open check to fail",
			source: `
resource "aws_eks_cluster" "bad_example" {

    name = "bad_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = true
		public_access_cidrs = [ "0.0.0.0/0" ]
    }
}
`,
		},
		{
			name: "Test public access cidrs actively set to open check to fail",
			source: `
resource "aws_eks_cluster" "bad_example" {

name = "bad_example_cluster"
role_arn = var.cluster_arn
vpc_config {
public_access_cidrs = [ "0.0.0.0/0" ]
}
}
`,
			mustIncludeResultCode: expectedCode,
		},

		{
			name: "Test public access cidrs using default set to open check to fail",
			source: `
resource "aws_eks_cluster" "bad_example" {

name = "bad_example_cluster"
role_arn = var.cluster_arn
vpc_config {
}
}
`,
			mustIncludeResultCode: expectedCode,
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

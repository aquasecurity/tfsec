package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSRedshiftNotDeployedInEC2Classic(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "TODO: add test name",
			source: `
resource "aws_redshift_cluster" "bad_example" {
	cluster_identifier = "tf-redshift-cluster"
	database_name      = "mydb"
	master_username    = "foo"
	master_password    = "Mustbe8characters"
	node_type          = "dc1.large"
	cluster_type       = "single-node"
}
`,
			mustIncludeResultCode: rules.AWSRedshiftNotDeployedInEC2Classic,
		},
		{
			name: "TODO: add test name",
			source: `
resource "aws_redshift_cluster" "good_example" {
	cluster_identifier = "tf-redshift-cluster"
	database_name      = "mydb"
	master_username    = "foo"
	master_password    = "Mustbe8characters"
	node_type          = "dc1.large"
	cluster_type       = "single-node"

	cluster_subnet_group_name = "redshift_subnet"
}
`,
			mustExcludeResultCode: rules.AWSRedshiftNotDeployedInEC2Classic,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

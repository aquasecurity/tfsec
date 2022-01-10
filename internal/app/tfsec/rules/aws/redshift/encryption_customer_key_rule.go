package redshift

import (
	"github.com/aquasecurity/defsec/rules/aws/redshift"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS094",
		BadExample: []string{`
 resource "aws_redshift_cluster" "bad_example" {
   cluster_identifier = "tf-redshift-cluster"
   database_name      = "mydb"
   master_username    = "foo"
   master_password    = "Mustbe8characters"
   node_type          = "dc1.large"
   cluster_type       = "single-node"
 }
 `},
		GoodExample: []string{`
 resource "aws_kms_key" "redshift" {
 	enable_key_rotation = true
 }
 
 resource "aws_redshift_cluster" "good_example" {
   cluster_identifier = "tf-redshift-cluster"
   database_name      = "mydb"
   master_username    = "foo"
   master_password    = "Mustbe8characters"
   node_type          = "dc1.large"
   cluster_type       = "single-node"
   encrypted          = true
   kms_key_id         = aws_kms_key.redshift.key_id
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#encrypted",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_redshift_cluster"},
		Base:           redshift.CheckEncryptionCustomerKey,
	})
}

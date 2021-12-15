package redshift

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/redshift"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_redshift_cluster"},
		Base:           redshift.CheckEncryptionCustomerKey,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("encrypted") {
				results.Add("Resource does not have encryption enabled", resourceBlock)
				return
			}

			encryptedAttr := resourceBlock.GetAttribute("encrypted")
			if encryptedAttr.IsFalse() {
				results.Add("Resource has encryption explicitly disabled", encryptedAttr)
				return
			}

			if resourceBlock.MissingChild("kms_key_id") {
				results.Add("Resource does not have a customer managed key specified", resourceBlock)
			}

			return results
		},
	})
}

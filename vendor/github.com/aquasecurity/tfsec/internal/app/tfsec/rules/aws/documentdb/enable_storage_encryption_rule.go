package documentdb

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/documentdb"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "aws_docdb_cluster" "bad_example" {
   cluster_identifier      = "my-docdb-cluster"
   engine                  = "docdb"
   master_username         = "foo"
   master_password         = "mustbeeightchars"
   backup_retention_period = 5
   preferred_backup_window = "07:00-09:00"
   skip_final_snapshot     = true
   storage_encrypted = false
 }
 `},
		GoodExample: []string{`
 resource "aws_docdb_cluster" "good_example" {
   cluster_identifier      = "my-docdb-cluster"
   engine                  = "docdb"
   master_username         = "foo"
   master_password         = "mustbeeightchars"
   backup_retention_period = 5
   preferred_backup_window = "07:00-09:00"
   skip_final_snapshot     = true
   storage_encrypted = true
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#storage_encrypted",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"aws_docdb_cluster",
		},
		Base: documentdb.CheckEnableStorageEncryption,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if storageEncryptedAttr := resourceBlock.GetAttribute("storage_encrypted"); storageEncryptedAttr.IsNil() { // alert on use of default value
				results.Add("Resource uses default value for storage_encrypted", resourceBlock)
			} else if storageEncryptedAttr.IsFalse() {
				results.Add("Resource does not have storage_encrypted set to true", storageEncryptedAttr)
			}
			return results
		},
	})
}

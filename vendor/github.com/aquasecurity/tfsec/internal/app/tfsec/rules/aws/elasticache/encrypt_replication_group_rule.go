package elasticache

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/elasticache"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS035",
		BadExample: []string{`
 resource "aws_elasticache_replication_group" "bad_example" {
         replication_group_id = "foo"
         replication_group_description = "my foo cluster"
 
         at_rest_encryption_enabled = false
 }
 `},
		GoodExample: []string{`
 resource "aws_elasticache_replication_group" "good_example" {
         replication_group_id = "foo"
         replication_group_description = "my foo cluster"
 
         at_rest_encryption_enabled = true
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#at_rest_encryption_enabled",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticache_replication_group"},
		Base:           elasticache.CheckEnableAtRestEncryption,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			encryptionAttr := resourceBlock.GetAttribute("at_rest_encryption_enabled")
			if encryptionAttr.IsNil() {
				results.Add("Resource defines an unencrypted Elasticache Replication Group (missing at_rest_encryption_enabled attribute).", resourceBlock)
			} else if !encryptionAttr.IsTrue() {
				results.Add("Resource defines an unencrypted Elasticache Replication Group (at_rest_encryption_enabled set to false).", encryptionAttr)
			}

			return results
		},
	})
}

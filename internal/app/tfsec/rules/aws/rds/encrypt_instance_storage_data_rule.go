package rds

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS052",
		BadExample: []string{`
 resource "aws_db_instance" "bad_example" {
 	
 }
 `},
		GoodExample: []string{`
 resource "aws_db_instance" "good_example" {
 	storage_encrypted  = true
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance",
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_instance"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("storage_encrypted") {
				results.Add("Resource has no storage encryption defined.", resourceBlock)
				return
			}

			storageEncryptedAttr := resourceBlock.GetAttribute("storage_encrypted")
			if storageEncryptedAttr.IsFalse() {
				results.Add("Resource has storage encrypted set to false", storageEncryptedAttr)
			}
			return results
		},
	})
}

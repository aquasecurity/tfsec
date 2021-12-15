package rds

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS051",
		BadExample: []string{`
 resource "aws_rds_cluster" "bad_example" {
   name       = "bar"
   kms_key_id = ""
 }`},
		GoodExample: []string{`
 resource "aws_rds_cluster" "good_example" {
   name              = "bar"
   kms_key_id  = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
   storage_encrypted = true
 }`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster",
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_rds_cluster"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			kmsKeyIdAttr := resourceBlock.GetAttribute("kms_key_id")
			storageEncryptedattr := resourceBlock.GetAttribute("storage_encrypted")

			if kmsKeyIdAttr.IsEmpty() && storageEncryptedattr.IsFalse() {
				results.Add("Resource defines a disabled RDS Cluster encryption.", kmsKeyIdAttr)
			} else if kmsKeyIdAttr.IsNotNil() && kmsKeyIdAttr.Equals("") {
				results.Add("Resource defines a disabled RDS Cluster encryption.", ?)
			} else if storageEncryptedattr.IsNil() || storageEncryptedattr.IsFalse() {
				results.Add("Resource defines a enabled RDS Cluster encryption but not the required encrypted_storage.", ?)
			}
			return results
		},
	})
}

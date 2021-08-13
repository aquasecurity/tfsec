package rds

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS051",
		Service:   "rds",
		ShortCode: "encrypt-cluster-storage-data",
		Documentation: rule.RuleDocumentation{
			Summary:    "There is no encryption specified or encryption is disabled on the RDS Cluster.",
			Impact:     "Data can be read from the RDS cluster if it is compromised",
			Resolution: "Enable encryption for RDS clusters",
			Explanation: `
Encryption should be enabled for an RDS Aurora cluster. 

When enabling encryption by setting the kms_key_id, the storage_encrypted must also be set to true. 
`,
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
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_rds_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			kmsKeyIdAttr := resourceBlock.GetAttribute("kms_key_id")
			storageEncryptedattr := resourceBlock.GetAttribute("storage_encrypted")

			if kmsKeyIdAttr.IsEmpty() && storageEncryptedattr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' defines a disabled RDS Cluster encryption.", resourceBlock.FullName())
			} else if kmsKeyIdAttr.IsNotNil() && kmsKeyIdAttr.Equals("") {
				set.AddResult().
					WithDescription("Resource '%s' defines a disabled RDS Cluster encryption.", resourceBlock.FullName())
			} else if storageEncryptedattr.IsNil() || storageEncryptedattr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' defines a enabled RDS Cluster encryption but not the required encrypted_storage.", resourceBlock.FullName())
			}
		},
	})
}

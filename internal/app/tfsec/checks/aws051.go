package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSRDSAuroraClusterEncryptionDisabled scanner.RuleCode = "AWS051"
const AWSRDSAuroraClusterEncryptionDisabledDescription scanner.RuleSummary = "There is no encryption specified or encryption is disabled on the RDS Cluster."
const AWSRDSAuroraClusterEncryptionDisabledExplanation = `
Encryption should be enabled for an RDS Aurora cluster. 

When enabling encryption by setting the kms_key_id, the storage_encrypted must also be set to true. 
`
const AWSRDSAuroraClusterEncryptionDisabledBadExample = `
resource "aws_rds_cluster" "foo" {
  name       = "bar"
  kms_key_id = ""
}`
const AWSRDSAuroraClusterEncryptionDisabledGoodExample = `
resource "aws_rds_cluster" "foo" {
  name              = "bar"
  kms_key_id  = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
  storage_encrypted = true
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSRDSAuroraClusterEncryptionDisabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSRDSAuroraClusterEncryptionDisabledDescription,
			Explanation: AWSRDSAuroraClusterEncryptionDisabledExplanation,
			BadExample:  AWSRDSAuroraClusterEncryptionDisabledBadExample,
			GoodExample: AWSRDSAuroraClusterEncryptionDisabledGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_rds_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			kmsKeyIdAttr := block.GetAttribute("kms_key_id")
			storageEncryptedattr := block.GetAttribute("storage_encrypted")

			if kmsKeyIdAttr == nil || kmsKeyIdAttr.IsEmpty() {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a disabled RDS Cluster encryption.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if kmsKeyIdAttr.Equals("") {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines a disabled RDS Cluster encryption.", block.FullName()),
						kmsKeyIdAttr.Range(),
						kmsKeyIdAttr,
						scanner.SeverityError,
					),
				}
			} else if storageEncryptedattr == nil || storageEncryptedattr.IsFalse() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines a enabled RDS Cluster encryption but not the required encrypted_storage.", block.FullName()),
						kmsKeyIdAttr.Range(),
						kmsKeyIdAttr,
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}

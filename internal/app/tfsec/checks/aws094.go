package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSRedshiftAtRestEncryption scanner.RuleCode = "AWS094"
const AWSRedshiftAtRestEncryptionDescription scanner.RuleSummary = "Redshift clusters should use at rest encryption"
const AWSRedshiftAtRestEncryptionImpact = "Data may be leaked if infrastructure is compromised"
const AWSRedshiftAtRestEncryptionResolution = "Enable encryption using CMK"
const AWSRedshiftAtRestEncryptionExplanation = `
Redshift clusters that contain sensitive data or are subject to regulation should be encrypted at rest to prevent data leakage should the infrastructure be compromised.
`
const AWSRedshiftAtRestEncryptionBadExample = `
resource "aws_redshift_cluster" "bad_example" {
  cluster_identifier = "tf-redshift-cluster"
  database_name      = "mydb"
  master_username    = "foo"
  master_password    = "Mustbe8characters"
  node_type          = "dc1.large"
  cluster_type       = "single-node"
}
`
const AWSRedshiftAtRestEncryptionGoodExample = `
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
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSRedshiftAtRestEncryption,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSRedshiftAtRestEncryptionDescription,
			Explanation: AWSRedshiftAtRestEncryptionExplanation,
			Impact:      AWSRedshiftAtRestEncryptionImpact,
			Resolution:  AWSRedshiftAtRestEncryptionResolution,
			BadExample:  AWSRedshiftAtRestEncryptionBadExample,
			GoodExample: AWSRedshiftAtRestEncryptionGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#encrypted",
				"https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_redshift_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("encrypted") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have encryption enabled", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			}

			if block.MissingChild("kms_key_id") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have a customer managed key specified", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			}

			encryptedAttr := block.GetAttribute("encrypted")
			if encryptedAttr.IsFalse() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' has encryption explicitly dissabled", block.FullName()),
						encryptedAttr.Range(),
						encryptedAttr,
						scanner.SeverityWarning,
					),
				}
			}

			return nil
		},
	})
}

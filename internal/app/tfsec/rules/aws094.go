package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSRedshiftAtRestEncryption = "AWS094"
const AWSRedshiftAtRestEncryptionDescription = "Redshift clusters should use at rest encryption"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSRedshiftAtRestEncryption,
		Documentation: rule.RuleDocumentation{
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
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_redshift_cluster"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {

			if block.MissingChild("encrypted") {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' does not have encryption enabled", block.FullName()),
						).WithRange(block.Range()).WithSeverity(
						severity.Warning,
					),
				}
			}

			if block.MissingChild("kms_key_id") {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' does not have a customer managed key specified", block.FullName()),
						).WithRange(block.Range()).WithSeverity(
						severity.Warning,
					),
				}
			}

			encryptedAttr := block.GetAttribute("encrypted")
			if encryptedAttr.IsFalse() {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' has encryption explicitly dissabled", block.FullName()),
						encryptedAttr.Range(),
						encryptedAttr,
						severity.Warning,
					),
				}
			}

			return nil
		},
	})
}

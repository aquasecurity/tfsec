package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
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
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_redshift_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("encrypted") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not have encryption enabled", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			encryptedAttr := resourceBlock.GetAttribute("encrypted")
			if encryptedAttr.IsFalse() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' has encryption explicitly disabled", resourceBlock.FullName())).
						WithRange(encryptedAttr.Range()).
						WithAttributeAnnotation(encryptedAttr),
				)
				return
			}

			if resourceBlock.MissingChild("kms_key_id") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not have a customer managed key specified", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			}

		},
	})
}

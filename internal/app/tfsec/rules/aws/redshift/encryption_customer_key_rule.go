package redshift

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
		LegacyID:  "AWS094",
		Service:   "redshift",
		ShortCode: "encryption-customer-key",
		Documentation: rule.RuleDocumentation{
			Summary: "Redshift clusters should use at rest encryption",
			Explanation: `
Redshift clusters that contain sensitive data or are subject to regulation should be encrypted at rest to prevent data leakage should the infrastructure be compromised.
`,
			Impact:     "Data may be leaked if infrastructure is compromised",
			Resolution: "Enable encryption using CMK",
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
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_redshift_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("encrypted") {
				set.AddResult().
					WithDescription("Resource '%s' does not have encryption enabled", resourceBlock.FullName())
				return
			}

			encryptedAttr := resourceBlock.GetAttribute("encrypted")
			if encryptedAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' has encryption explicitly disabled", resourceBlock.FullName()).
					WithAttribute(encryptedAttr)
				return
			}

			if resourceBlock.MissingChild("kms_key_id") {
				set.AddResult().
					WithDescription("Resource '%s' does not have a customer managed key specified", resourceBlock.FullName())
			}

		},
	})
}

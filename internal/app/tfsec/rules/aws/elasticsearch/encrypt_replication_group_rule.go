package elasticsearch

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
		LegacyID:  "AWS035",
		Service:   "elastic-search",
		ShortCode: "encrypt-replication-group",
		Documentation: rule.RuleDocumentation{
			Summary:    "Unencrypted Elasticache Replication Group.",
			Impact:     "Data in the replication group could be readable if compromised",
			Resolution: "Enable encryption for replication group",
			Explanation: `
You should ensure your Elasticache data is encrypted at rest to help prevent sensitive information from being read by unauthorised users.
`,
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
				"https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticache_replication_group"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context block.Module) {

			encryptionAttr := resourceBlock.GetAttribute("at_rest_encryption_enabled")
			if encryptionAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted Elasticache Replication Group (missing at_rest_encryption_enabled attribute).", resourceBlock.FullName())
			} else if !encryptionAttr.IsTrue() {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted Elasticache Replication Group (at_rest_encryption_enabled set to false).", resourceBlock.FullName()).
					WithAttribute(encryptionAttr)
			}

		},
	})
}

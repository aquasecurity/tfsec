package elasticache

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
		LegacyID:  "AWS036",
		Service:   "elasticache",
		ShortCode: "enable-in-transit-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "Elasticache Replication Group uses unencrypted traffic.",
			Impact:     "In transit data in the Replication Group could be read if intercepted",
			Resolution: "Enable in transit encryption for replication group",
			Explanation: `
Traffic flowing between Elasticache replication nodes should be encrypted to ensure sensitive data is kept private.
`,
			BadExample: []string{`
resource "aws_elasticache_replication_group" "bad_example" {
        replication_group_id = "foo"
        replication_group_description = "my foo cluster"

        transit_encryption_enabled = false
}
`},
			GoodExample: []string{`
resource "aws_elasticache_replication_group" "good_example" {
        replication_group_id = "foo"
        replication_group_description = "my foo cluster"

        transit_encryption_enabled = true
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#transit_encryption_enabled",
				"https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticache_replication_group"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context block.Module) {

			encryptionAttr := resourceBlock.GetAttribute("transit_encryption_enabled")
			if encryptionAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted Elasticache Replication Group (missing transit_encryption_enabled attribute).", resourceBlock.FullName())
			} else if !encryptionAttr.IsTrue() {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted Elasticache Replication Group (transit_encryption_enabled set to false).", resourceBlock.FullName()).
					WithAttribute(encryptionAttr)

			}

		},
	})
}

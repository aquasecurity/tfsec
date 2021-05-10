package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSUnencryptedInTransitElasticacheReplicationGroup scanner.RuleCode = "AWS036"
const AWSUnencryptedInTransitElasticacheReplicationGroupDescription scanner.RuleSummary = "Elasticache Replication Group uses unencrypted traffic."
const AWSUnencryptedInTransitElasticacheReplicationGroupImpact = "In transit data in the Replication Group could be read if intercepted"
const AWSUnencryptedInTransitElasticacheReplicationGroupResolution = "Enable in transit encryptuon for replication group"
const AWSUnencryptedInTransitElasticacheReplicationGroupExplanation = `
Traffic flowing between Elasticache replication nodes should be encrypted to ensure sensitive data is kept private.
`
const AWSUnencryptedInTransitElasticacheReplicationGroupBadExample = `
resource "aws_elasticache_replication_group" "bad_example" {
        replication_group_id = "foo"
        replication_group_description = "my foo cluster"

        transit_encryption_enabled = false
}
`
const AWSUnencryptedInTransitElasticacheReplicationGroupGoodExample = `
resource "aws_elasticache_replication_group" "good_example" {
        replication_group_id = "foo"
        replication_group_description = "my foo cluster"

        transit_encryption_enabled = true
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSUnencryptedInTransitElasticacheReplicationGroup,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSUnencryptedInTransitElasticacheReplicationGroupDescription,
			Impact:      AWSUnencryptedInTransitElasticacheReplicationGroupImpact,
			Resolution:  AWSUnencryptedInTransitElasticacheReplicationGroupResolution,
			Explanation: AWSUnencryptedInTransitElasticacheReplicationGroupExplanation,
			BadExample:  AWSUnencryptedInTransitElasticacheReplicationGroupBadExample,
			GoodExample: AWSUnencryptedInTransitElasticacheReplicationGroupGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#transit_encryption_enabled",
				"https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticache_replication_group"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			encryptionAttr := block.GetAttribute("transit_encryption_enabled")
			if encryptionAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted Elasticache Replication Group (missing transit_encryption_enabled attribute).", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if !isBooleanOrStringTrue(encryptionAttr) {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines an unencrypted Elasticache Replication Group (transit_encryption_enabled set to false).", block.FullName()),
						encryptionAttr.Range(),
						encryptionAttr,
						scanner.SeverityError,
					),
				}

			}

			return nil
		},
	})
}

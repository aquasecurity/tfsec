package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSUnencryptedInTransitElasticacheReplicationGroup See https://github.com/tfsec/tfsec#included-checks for check info
const AWSUnencryptedInTransitElasticacheReplicationGroup scanner.RuleID = "AWS036"
const AWSUnencryptedInTransitElasticacheReplicationGroupDescription scanner.RuleSummary = "Elasticache Replication Group uses unencrypted traffic."
const AWSUnencryptedInTransitElasticacheReplicationGroupExplanation = `

`
const AWSUnencryptedInTransitElasticacheReplicationGroupBadExample = `

`
const AWSUnencryptedInTransitElasticacheReplicationGroupGoodExample = `

`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSUnencryptedInTransitElasticacheReplicationGroup,
		Documentation: scanner.CheckDocumentation{
			Summary: AWSUnencryptedInTransitElasticacheReplicationGroupDescription,
            Explanation: AWSUnencryptedInTransitElasticacheReplicationGroupExplanation,
            BadExample:  AWSUnencryptedInTransitElasticacheReplicationGroupBadExample,
            GoodExample: AWSUnencryptedInTransitElasticacheReplicationGroupGoodExample,
            Links: []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticache_replication_group"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			encryptionAttr := block.GetAttribute("transit_encryption_enabled")
			if encryptionAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted Elasticache Replication Group (missing transit_encryption_enabled attribute).", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if !isBooleanOrStringTrue(encryptionAttr) {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines an unencrypted Elasticache Replication Group (transit_encryption_enabled set to false).", block.Name()),
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

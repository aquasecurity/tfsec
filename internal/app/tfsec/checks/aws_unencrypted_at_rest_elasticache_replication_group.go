package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSUnencryptedAtRestElasticacheReplicationGroup See https://github.com/tfsec/tfsec#included-checks for check info
const AWSUnencryptedAtRestElasticacheReplicationGroup scanner.RuleID = "AWS035"
const AWSUnencryptedAtRestElasticacheReplicationGroupDescription scanner.RuleDescription = "Unencrypted Elasticache Replication Group."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSUnencryptedAtRestElasticacheReplicationGroup,
		Description:    AWSUnencryptedAtRestElasticacheReplicationGroupDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticache_replication_group"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			encryptionAttr := block.GetAttribute("at_rest_encryption_enabled")
			if encryptionAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted Elasticache Replication Group (missing at_rest_encryption_enabled attribute).", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if !isBooleanOrStringTrue(encryptionAttr) {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines an unencrypted Elasticache Replication Group (at_rest_encryption_enabled set to false).", block.Name()),
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

package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
)

// GoogleUnencryptedStorageBucket See https://github.com/liamg/tfsec#included-checks for check info
const GoogleUnencryptedStorageBucket scanner.RuleID = "GCP002"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           GoogleUnencryptedStorageBucket,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_storage_bucket"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			encryptionBlock := block.GetBlock("encryption")
			if encryptionBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted storage bucket.", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}

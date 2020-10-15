package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// GoogleUnencryptedStorageBucket See https://github.com/tfsec/tfsec#included-checks for check info
const GoogleUnencryptedStorageBucket scanner.RuleID = "GCP002"
const GoogleUnencryptedStorageBucketDescription scanner.RuleSummary = "Unencrypted storage bucket."
const GoogleUnencryptedStorageBucketExplanation = `

`
const GoogleUnencryptedStorageBucketBadExample = `

`
const GoogleUnencryptedStorageBucketGoodExample = `

`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GoogleUnencryptedStorageBucket,
		Documentation: scanner.CheckDocumentation{
			Summary: GoogleUnencryptedStorageBucketDescription,
            Explanation: GoogleUnencryptedStorageBucketExplanation,
            BadExample:  GoogleUnencryptedStorageBucketBadExample,
            GoodExample: GoogleUnencryptedStorageBucketGoodExample,
            Links: []string{},
		},
		Provider:       scanner.GCPProvider,
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

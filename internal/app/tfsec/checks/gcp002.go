package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// GoogleUnencryptedStorageBucket See https://github.com/tfsec/tfsec#included-checks for check info
const GoogleUnencryptedStorageBucket scanner.RuleCode = "GCP002"
const GoogleUnencryptedStorageBucketDescription scanner.RuleSummary = "Unencrypted storage bucket."
const GoogleUnencryptedStorageBucketExplanation = `
Google storage buckets should have an <code>encryption</code> block to ensure that the data is encrypted at rest.

When specifying an <code>encryption</code> block, by not including the optional <code>default_kms_key_name</code> you are deferring to Google Provided Encryption.
`
const GoogleUnencryptedStorageBucketBadExample = `
resource "google_storage_bucket" "my-bucket" {
	# ...
	# no encryption block specified
	# ...
}`
const GoogleUnencryptedStorageBucketGoodExample = `
resource "google_storage_bucket" "my-bucket" {
	encryption {}	
}

resource "google_storage_bucket" "my-bucket" {
	encryption {
		default_kms_key_name = "my-key"
	}	
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GoogleUnencryptedStorageBucket,
		Documentation: scanner.CheckDocumentation{
			Summary:     GoogleUnencryptedStorageBucketDescription,
			Explanation: GoogleUnencryptedStorageBucketExplanation,
			BadExample:  GoogleUnencryptedStorageBucketBadExample,
			GoodExample: GoogleUnencryptedStorageBucketGoodExample,
			Links: []string{
				"https://cloud.google.com/storage/docs/json_api/v1/buckets",
				"https://www.terraform.io/docs/providers/google/r/storage_bucket.html",
			},
		},
		Provider:       scanner.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_storage_bucket"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			encryptionBlock := block.GetBlock("encryption")
			if encryptionBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted storage bucket.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}

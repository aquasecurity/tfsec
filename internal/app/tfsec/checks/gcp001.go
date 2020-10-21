package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// GoogleUnencryptedDisk See https://github.com/tfsec/tfsec#included-checks for check info
const GoogleUnencryptedDisk scanner.RuleCode = "GCP001"
const GoogleUnencryptedDiskDescription scanner.RuleSummary = "Unencrypted compute disk."
const GoogleUnencryptedDiskExplanation = `
By default, Compute Engine encrypts all data at rest. Compute Engine handles and manages this encryption for you without any additional actions on your part.

If the <code>disk_encryption_key</code> block is included in the resource declaration then it *must* include a <code>raw_key</code> or <code>kms_key_self_link</code>.

To use the default offering of Google managed keys, do not include a <code>disk_encryption_key</code> block at all.
`
const GoogleUnencryptedDiskBadExample = `
resource "google_compute_disk" "my-disk" {
	# ... 
	disk_encryption_key {}
	# ...
}`
const GoogleUnencryptedDiskGoodExample = `
resource "google_compute_disk" "my-disk" {
	disk_encryption_key {
		kms_key_self_link = "something"
	}
}

resource "google_compute_disk" "another-my-disk" {
	disk_encryption_key {
		raw_key = "something"
	}
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GoogleUnencryptedDisk,
		Documentation: scanner.CheckDocumentation{
			Summary:     GoogleUnencryptedDiskDescription,
			Explanation: GoogleUnencryptedDiskExplanation,
			BadExample:  GoogleUnencryptedDiskBadExample,
			GoodExample: GoogleUnencryptedDiskGoodExample,
			Links: []string{
				"https://cloud.google.com/compute/docs/disks/customer-supplied-encryption",
				"https://www.terraform.io/docs/providers/google/r/compute_disk.html",
			},
		},
		Provider:       scanner.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_compute_disk"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			keyBlock := block.GetBlock("disk_encryption_key")
			if keyBlock != nil {
				if keyBlock.GetAttribute("raw_key") == nil && keyBlock.GetAttribute("kms_key_self_link") == nil {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' defines an unencrypted disk. You should specify raw_key or kms_key_self_link.", block.FullName()),
							keyBlock.Range(),
							scanner.SeverityError,
						),
					}

				}
			}
			return nil
		},
	})
}

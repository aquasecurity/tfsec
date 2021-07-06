package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// GoogleUnencryptedDisk See https://github.com/tfsec/tfsec#included-checks for check info
const GoogleUnencryptedDisk = "GCP001"
const GoogleUnencryptedDiskDescription = "Unencrypted compute disk."
const GoogleUnencryptedDiskImpact = "Data could be readable if compromised"
const GoogleUnencryptedDiskResolution = "Enable encrytion for compute disks"
const GoogleUnencryptedDiskExplanation = `
By default, Compute Engine encrypts all data at rest. Compute Engine handles and manages this encryption for you without any additional actions on your part.

If the <code>disk_encryption_key</code> block is included in the resource declaration then it *must* include a <code>raw_key</code> or <code>kms_key_self_link</code>.

To use the default offering of Google managed keys, do not include a <code>disk_encryption_key</code> block at all.
`
const GoogleUnencryptedDiskBadExample = `
resource "google_compute_disk" "bad_example" {
	# ... 
	disk_encryption_key {}
	# ...
}`
const GoogleUnencryptedDiskGoodExample = `
resource "google_compute_disk" "good_example" {
	disk_encryption_key {
		kms_key_self_link = "something"
	}
}

resource "google_compute_disk" "good_example" {
	disk_encryption_key {
		raw_key = "something"
	}
}`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: GoogleUnencryptedDisk,
		Documentation: rule.RuleDocumentation{
			Summary:     GoogleUnencryptedDiskDescription,
			Impact:      GoogleUnencryptedDiskImpact,
			Resolution:  GoogleUnencryptedDiskResolution,
			Explanation: GoogleUnencryptedDiskExplanation,
			BadExample:  GoogleUnencryptedDiskBadExample,
			GoodExample: GoogleUnencryptedDiskGoodExample,
			Links: []string{
				"https://cloud.google.com/compute/docs/disks/customer-supplied-encryption",
				"https://www.terraform.io/docs/providers/google/r/compute_disk.html",
			},
		},
		Provider:        provider.GCPProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_compute_disk"},
		DefaultSeverity: severity.Error,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			keyBlock := resourceBlock.GetBlock("disk_encryption_key")
			if keyBlock != nil {
				if keyBlock.GetAttribute("raw_key") == nil && keyBlock.GetAttribute("kms_key_self_link") == nil {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' defines an unencrypted disk. You should specify raw_key or kms_key_self_link.", resourceBlock.FullName())).
							WithRange(keyBlock.Range()).
							WithSeverity(severity.Error),
					)
				}
			}
		},
	})
}

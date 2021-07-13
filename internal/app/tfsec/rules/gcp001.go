package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const GoogleUnencryptedDisk = "GCP001"
const GoogleUnencryptedDiskDescription = "Encrypted compute disk with unmanaged keys."
const GoogleUnencryptedDiskImpact = "Encryption of disk using unmanaged keys."
const GoogleUnencryptedDiskResolution = "Enable encryption using a customer-managed key."
const GoogleUnencryptedDiskExplanation = `
By default, Compute Engine encrypts all data at rest. Compute Engine handles and manages this encryption for you without any additional actions on your part.

If the <code>disk_encryption_key</code> block is included in the resource declaration then it *must* include a <code>raw_key</code> or <code>kms_key_self_link</code>.
`
const GoogleUnencryptedDiskBadExample = `
resource "google_compute_disk" "bad_example" {
	# ...
}`
const GoogleUnencryptedDiskGoodExample = `
resource "google_compute_disk" "good_example" {
	disk_encryption_key {
		kms_key_self_link = "something"
	}
}

`

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
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			keyBlock := resourceBlock.GetBlock("disk_encryption_key")
			if keyBlock == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a disk encrypted with an auto-generated key.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			}
		},
	})
}

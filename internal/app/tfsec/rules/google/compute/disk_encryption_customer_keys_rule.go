package compute

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
		LegacyID:  "GCP001",
		Service:   "compute",
		ShortCode: "disk-encryption-customer-keys",
		Documentation: rule.RuleDocumentation{
			Summary:    "Encrypted compute disk with unmanaged keys.",
			Impact:     "Encryption of disk using unmanaged keys.",
			Resolution: "Enable encryption using a customer-managed key.",
			Explanation: `
By default, Compute Engine encrypts all data at rest. Compute Engine handles and manages this encryption for you without any additional actions on your part.

If the <code>disk_encryption_key</code> block is included in the resource declaration then it *must* include a <code>raw_key</code> or <code>kms_key_self_link</code>.
`,
			BadExample: []string{`
resource "google_compute_disk" "bad_example" {
	# ...
}`},
			GoodExample: []string{`
resource "google_compute_disk" "good_example" {
	disk_encryption_key {
		kms_key_self_link = "something"
	}
}

`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk",
				"https://cloud.google.com/compute/docs/disks/customer-supplied-encryption",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_compute_disk"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("disk_encryption_key") {
				set.AddResult().
					WithDescription("Resource '%s' defines a disk encrypted with an auto-generated key.", resourceBlock.FullName())
			}
		},
	})
}

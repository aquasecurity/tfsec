package compute

// generator-locked
import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "GCP013",
		Service:   "compute",
		ShortCode: "disk-encryption-required",
		Documentation: rule.RuleDocumentation{
			Summary: "The encryption key used to encrypt a compute disk has been specified in plaintext.",
			Explanation: `
Sensitive values such as raw encryption keys should not be included in your Terraform code, and should be stored securely by a secrets manager.
`,
			Impact:     "The encryption key should be considered compromised as it is not stored securely.",
			Resolution: "Reference a managed key rather than include the key in raw format.",
			BadExample: []string{`
resource "google_compute_disk" "good_example" {
	disk_encryption_key {
		raw_key="b2ggbm8gdGhpcyBpcyBiYWQ="
	}
}
`},
			GoodExample: []string{`
resource "google_compute_disk" "good_example" {
	disk_encryption_key {
		kms_key_self_link = google_kms_crypto_key.my_crypto_key.id
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#kms_key_self_link",
				"https://cloud.google.com/compute/docs/disks/customer-supplied-encryption",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_compute_disk"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("disk_encryption_key") {
				return
			}

			if resourceBlock.MissingNestedChild("disk_encryption_key.raw_key") {
				return
			}

			rawKeyAttr := resourceBlock.GetNestedAttribute("disk_encryption_key.raw_key")

			if rawKeyAttr.IsString() {
				set.AddResult().
					WithDescription("Resource '%s' specifies an encryption key in raw format.", resourceBlock.FullName()).
					WithAttribute(rawKeyAttr)
			}

		},
	})
}

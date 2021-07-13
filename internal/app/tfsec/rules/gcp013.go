package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

const GCPRawEncryptionKeySpecifiedForComputeDisk = "GCP013"
const GCPRawEncryptionKeySpecifiedForComputeDiskDescription = "The encryption key used to encrypt a compute disk has been specified in plaintext."
const GCPRawEncryptionKeySpecifiedForComputeDiskImpact = "The encryption key should be considered compromised as it is not stored securely."
const GCPRawEncryptionKeySpecifiedForComputeDiskResolution = "Reference a managed key rather than include the key in raw format."
const GCPRawEncryptionKeySpecifiedForComputeDiskExplanation = `
Sensitive values such as raw encryption keys should not be included in your Terraform code, and should be stored securely by a secrets manager.
`
const GCPRawEncryptionKeySpecifiedForComputeDiskBadExample = `
resource "google_compute_disk" "good_example" {
	disk_encryption_key {
		raw_key="b2ggbm8gdGhpcyBpcyBiYWQ="
	}
}
`
const GCPRawEncryptionKeySpecifiedForComputeDiskGoodExample = `
resource "google_compute_disk" "good_example" {
	disk_encryption_key {
		kms_key_self_link = google_kms_crypto_key.my_crypto_key.id
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: GCPRawEncryptionKeySpecifiedForComputeDisk,
		Documentation: rule.RuleDocumentation{
			Summary:     GCPRawEncryptionKeySpecifiedForComputeDiskDescription,
			Explanation: GCPRawEncryptionKeySpecifiedForComputeDiskExplanation,
			Impact:      GCPRawEncryptionKeySpecifiedForComputeDiskImpact,
			Resolution:  GCPRawEncryptionKeySpecifiedForComputeDiskResolution,
			BadExample:  GCPRawEncryptionKeySpecifiedForComputeDiskBadExample,
			GoodExample: GCPRawEncryptionKeySpecifiedForComputeDiskGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#kms_key_self_link",
				"https://cloud.google.com/compute/docs/disks/customer-supplied-encryption",
			},
		},
		Provider:        provider.GCPProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_compute_disk"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			keyBlock := resourceBlock.GetBlock("disk_encryption_key")
			if keyBlock == nil {
				return
			}

			rawKeyAttr := keyBlock.GetAttribute("raw_key")
			if rawKeyAttr == nil {
				return
			}

			if rawKeyAttr.IsString() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' specifies an encryption key in raw format.", resourceBlock.FullName())).
						WithRange(rawKeyAttr.Range()).
						WithAttributeAnnotation(rawKeyAttr),
				)
			}

		},
	})
}

package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// GoogleUnencryptedDisk See https://github.com/tfsec/tfsec#included-checks for check info
const GoogleUnencryptedDisk scanner.RuleID = "GCP001"
const GoogleUnencryptedDiskDescription scanner.RuleDescription = "Unencrypted compute disk."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           GoogleUnencryptedDisk,
		Description:    GoogleUnencryptedDiskDescription,
		Provider:       scanner.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_compute_disk"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			keyBlock := block.GetBlock("disk_encryption_key")
			if keyBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted disk.", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			if keyBlock.GetAttribute("raw_key") == nil && keyBlock.GetAttribute("kms_key_self_link") == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted disk. You should specify raw_key or kms_key_self_link.", block.Name()),
						keyBlock.Range(),
						scanner.SeverityError,
					),
				}

			}

			return nil
		},
	})
}

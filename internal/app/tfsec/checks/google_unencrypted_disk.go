package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
)

// GoogleUnencryptedDisk See https://github.com/liamg/tfsec#included-checks for check info
const GoogleUnencryptedDisk scanner.CheckCode = "GCP001"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           GoogleUnencryptedDisk,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_compute_disk"},
		CheckFunc: func(check *scanner.Check, block *parser.Block) []scanner.Result {

			keyBlock := block.GetBlock("disk_encryption_key")
			if keyBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted disk.", block.Name()),
						block.Range(),
					),
				}
			}

			if keyBlock.GetAttribute("raw_key") == nil && keyBlock.GetAttribute("kms_key_self_link") == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted disk. You should specify raw_key or kms_key_self_link.", block.Name()),
						keyBlock.Range(),
					),
				}

			}

			return nil
		},
	})
}

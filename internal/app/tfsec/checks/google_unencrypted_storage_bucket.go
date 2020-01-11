package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
)

// GoogleUnencryptedStorageBucket See https://github.com/liamg/tfsec#included-checks for check info
const GoogleUnencryptedStorageBucket scanner.RuleID = "GCP002"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           GoogleUnencryptedStorageBucket,
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

			if kmsAttr := encryptionBlock.GetAttribute("default_kms_key_name"); kmsAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted storage bucket. You should specify default_kms_key_name to enable encryption.", block.Name()),
						encryptionBlock.Range(),
						scanner.SeverityError,
					),
				}
			} else if kmsAttr.Type() != cty.String || kmsAttr.Value().AsString() == "" {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines an unencrypted storage bucket. The specified default_kms_key_name is empty.", block.Name()),
						kmsAttr.Range(),
						kmsAttr,
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}

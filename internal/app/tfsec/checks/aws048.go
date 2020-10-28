package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"
)

const AWSEfsEncryptionNotEnabled scanner.RuleCode = "AWS048"
const AWSEfsEncryptionNotEnabledDescription scanner.RuleSummary = "EFS Encryption has not been enabled"
const AWSEfsEncryptionNotEnabledExplanation = `
If your organization is subject to corporate or regulatory policies that require encryption of data and metadata at rest, we recommend creating a file system that is encrypted at rest, and mounting your file system using encryption of data in transit.

`
const AWSEfsEncryptionNotEnabledBadExample = `
resource "aws_efs_file_system" "foo" {
  name       = "bar"
  encrypted  = false
  kms_key_id = ""
}`
const AWSEfsEncryptionNotEnabledGoodExample = `
resource "aws_efs_file_system" "foo" {
  name       = "bar"
  encrypted  = true
  kms_key_id = "my_kms_key"
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSEfsEncryptionNotEnabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSEfsEncryptionNotEnabledDescription,
			Explanation: AWSEfsEncryptionNotEnabledExplanation,
			BadExample:  AWSEfsEncryptionNotEnabledBadExample,
			GoodExample: AWSEfsEncryptionNotEnabledGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/efs/latest/ug/encryption.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_efs_file_system"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			efsEnabledAttr := block.GetAttribute("encrypted")

			if efsEnabledAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not specify if encryption should be used.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if efsEnabledAttr.Type() == cty.Bool && efsEnabledAttr.Value().False() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' actively does not have encryption applied.", block.FullName()),
						efsEnabledAttr.Range(),
						efsEnabledAttr,
						scanner.SeverityError,
					),
				}
			}
			return nil

			return nil
		},
	})
}

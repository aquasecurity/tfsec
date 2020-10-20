package checks

import (
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSUnencryptedKinesisStream scanner.RuleCode = "AWS024"
const AWSUnencryptedKinesisStreamDescription scanner.RuleSummary = "Kinesis stream is unencrypted."
const AWSUnencryptedKinesisStreamExplanation = `
Kinesis streams should be encrypted to ensure sensitive data is kept private. Additionally, non-default KMS keys should be used so granularity of access control can be ensured.
`
const AWSUnencryptedKinesisStreamBadExample = `
resource "aws_kinesis_stream" "test_stream" {
	encryption_type = "NONE"
}
`
const AWSUnencryptedKinesisStreamGoodExample = `
resource "aws_kinesis_stream" "test_stream" {
	encryption_type = "KMS"
	kms_key_id = "my/special/key"
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSUnencryptedKinesisStream,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSUnencryptedKinesisStreamDescription,
			Explanation: AWSUnencryptedKinesisStreamExplanation,
			BadExample:  AWSUnencryptedKinesisStreamBadExample,
			GoodExample: AWSUnencryptedKinesisStreamGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_kinesis_stream"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			encryptionTypeAttr := block.GetAttribute("encryption_type")
			if encryptionTypeAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted Kinesis Stream.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if encryptionTypeAttr.Type() == cty.String && strings.ToUpper(encryptionTypeAttr.Value().AsString()) != "KMS" {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines an unencrypted Kinesis Stream.", block.FullName()),
						encryptionTypeAttr.Range(),
						encryptionTypeAttr,
						scanner.SeverityError,
					),
				}
			} else {
				keyIDAttr := block.GetAttribute("kms_key_id")
				if keyIDAttr == nil || keyIDAttr.Value().AsString() == "" || keyIDAttr.Value().AsString() == "alias/aws/kinesis" {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' defines a Kinesis Stream encrypted with the default Kinesis key.", block.FullName()),
							block.Range(),
							scanner.SeverityWarning,
						),
					}
				}
			}

			return nil
		},
	})
}

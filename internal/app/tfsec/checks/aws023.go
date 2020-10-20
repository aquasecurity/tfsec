package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSEcrImageScanNotEnabled See https://github.com/tfsec/tfsec#included-checks for check info
const AWSEcrImageScanNotEnabled scanner.RuleCode = "AWS023"
const AWSEcrImageScanNotEnabledDescription scanner.RuleSummary = "ECR repository has image scans disabled."
const AWSEcrImageScanNotEnabledExplanation = `
Repository image scans should be enabled to ensure vulnerable software can be discovered and remediated as soon as possible.
`
const AWSEcrImageScanNotEnabledBadExample = `
resource "aws_ecr_repository" "foo" {
  name                 = "bar"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
}
`
const AWSEcrImageScanNotEnabledGoodExample = `
resource "aws_ecr_repository" "foo" {
  name                 = "bar"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSEcrImageScanNotEnabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSEcrImageScanNotEnabledDescription,
			Explanation: AWSEcrImageScanNotEnabledExplanation,
			BadExample:  AWSEcrImageScanNotEnabledBadExample,
			GoodExample: AWSEcrImageScanNotEnabledGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecr_repository"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			ecrScanStatusBlock := block.GetBlock("image_scanning_configuration")
			ecrScanStatusAttr := ecrScanStatusBlock.GetAttribute("scan_on_push")

			if ecrScanStatusAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a disabled ECR image scan.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if ecrScanStatusAttr.Type() == cty.Bool && ecrScanStatusAttr.Value().False() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines a disabled ECR image scan.", block.FullName()),
						ecrScanStatusAttr.Range(),
						ecrScanStatusAttr,
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}

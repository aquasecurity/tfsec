package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSEcrImageScanNotEnabled See https://github.com/tfsec/tfsec#included-checks for check info
const AWSEcrImageScanNotEnabled scanner.RuleID = "AWS023"
const AWSEcrImageScanNotEnabledDescription scanner.RuleDescription = "ECR repository has image scans disabled."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSEcrImageScanNotEnabled,
		Description:    AWSEcrImageScanNotEnabledDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecr_repository"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			ecrScanStatusBlock := block.GetBlock("image_scanning_configuration")
			ecrScanStatusAttr := ecrScanStatusBlock.GetAttribute("scan_on_push")

			if ecrScanStatusAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a disabled ECR image scan.", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if ecrScanStatusAttr.Type() == cty.Bool && ecrScanStatusAttr.Value().False() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines a disabled ECR image scan.", block.Name()),
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

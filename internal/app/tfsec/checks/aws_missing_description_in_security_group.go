package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSNoDescriptionInSecurityGroup See https://github.com/tfsec/tfsec#included-checks for check info
const AWSNoDescriptionInSecurityGroup scanner.RuleID = "AWS018"
const AWSNoDescriptionInSecurityGroupDescription scanner.RuleDescription = "Missing description for security group/security group rule."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSNoDescriptionInSecurityGroup,
		Description:    AWSNoDescriptionInSecurityGroupDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group", "aws_security_group_rule"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			descriptionAttr := block.GetAttribute("description")
			if descriptionAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should include a description for auditing purposes.", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			if descriptionAttr.Type() == cty.String && descriptionAttr.Value().AsString() == "" {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' should include a non-empty description for auditing purposes.", block.Name()),
						descriptionAttr.Range(),
						descriptionAttr,
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}

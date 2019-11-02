package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSResourceHasPublicIP See https://github.com/liamg/tfsec#included-checks for check info
const AWSResourceHasPublicIP scanner.Code = "AWS012"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSResourceHasPublicIP,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_launch_configuration", "aws_instance"},
		CheckFunc: func(check *scanner.Check, block *parser.Block) []scanner.Result {

			if publicAttr := block.GetAttribute("associate_public_ip_address"); publicAttr != nil && publicAttr.Type() == cty.Bool {
				if publicAttr.Value().True() {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' has a public IP address associated.", block.Name()),
							publicAttr.Range(),
						),
					}
				}
			}

			return nil
		},
	})
}

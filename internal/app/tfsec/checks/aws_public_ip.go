package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSResourceHasPublicIP See https://github.com/liamg/tfsec#included-checks for check info
const AWSResourceHasPublicIP Code = "AWS012"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_launch_configuration", "aws_instance"},
		CheckFunc: func(block *parser.Block) []Result {

			if publicAttr := block.GetAttribute("associate_public_ip_address"); publicAttr != nil && publicAttr.Type() == cty.Bool {
				if publicAttr.Value().True() {
					return []Result{
						NewResult(
							AWSResourceHasPublicIP,
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

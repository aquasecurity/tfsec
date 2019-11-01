package checks

import (
	"fmt"
	"strings"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSOpenIngressSecurityGroupInlineRule See https://github.com/liamg/tfsec#included-checks for check info
const AWSOpenIngressSecurityGroupInlineRule Code = "AWS008"

// AWSOpenEgressSecurityGroupInlineRule See https://github.com/liamg/tfsec#included-checks for check info
const AWSOpenEgressSecurityGroupInlineRule Code = "AWS009"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group"},
		CheckFunc: func(block *parser.Block) []Result {

			var results []Result

			for _, direction := range []string{"ingress", "egress"} {

				code := AWSOpenIngressSecurityGroupInlineRule
				if direction == "egress" {
					code = AWSOpenEgressSecurityGroupInlineRule
				}

				if directionBlock := block.GetBlock(direction); directionBlock != nil {
					if cidrBlocksAttr := directionBlock.GetAttribute("cidr_blocks"); cidrBlocksAttr != nil {

						if cidrBlocksAttr.Value().LengthInt() == 0 {
							return nil
						}

						for _, cidr := range cidrBlocksAttr.Value().AsValueSlice() {
							if strings.HasSuffix(cidr.AsString(), "/0") {
								results = append(results,
									NewResult(
										code,
										fmt.Sprintf("Resource '%s' defines a fully open %s security group.", block.Name(), direction),
										cidrBlocksAttr.Range(),
									),
								)
							}
						}
					}
				}
			}

			return results
		},
	})
}

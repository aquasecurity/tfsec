package checks

import (
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSOpenIngressSecurityGroupRule See https://github.com/liamg/tfsec#included-checks for check info
const AWSOpenIngressSecurityGroupRule Code = "AWS006"

// AWSOpenEgressSecurityGroupRule See https://github.com/liamg/tfsec#included-checks for check info
const AWSOpenEgressSecurityGroupRule Code = "AWS007"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group_rule"},
		CheckFunc: func(block *parser.Block) []Result {

			typeAttr := block.GetAttribute("type")
			if typeAttr == nil || typeAttr.Type() != cty.String {
				return nil
			}

			code := AWSOpenIngressSecurityGroupRule
			if typeAttr.Value().AsString() == "egress" {
				code = AWSOpenEgressSecurityGroupRule
			}

			if cidrBlocksAttr := block.GetAttribute("cidr_blocks"); cidrBlocksAttr != nil {

				if cidrBlocksAttr.Value().LengthInt() == 0 {
					return nil
				}

				for _, cidr := range cidrBlocksAttr.Value().AsValueSlice() {
					if strings.HasSuffix(cidr.AsString(), "/0") {
						return []Result{
							NewResult(
								code,
								fmt.Sprintf("Resource '%s' defines a fully open %s security group rule.", block.Name(), typeAttr.Value().AsString()),
								cidrBlocksAttr.Range(),
							),
						}
					}
				}

			}

			return nil
		},
	})
}

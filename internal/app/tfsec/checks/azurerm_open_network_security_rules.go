package checks

import (
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AzureOpenInboundNetworkSecurityGroupRule See https://github.com/liamg/tfsec#included-checks for check info
const AzureOpenInboundNetworkSecurityGroupRule Code = "AZU001"

// AzureOpenOutboundNetworkSecurityGroupRule See https://github.com/liamg/tfsec#included-checks for check info
const AzureOpenOutboundNetworkSecurityGroupRule Code = "AZU002"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_network_security_rule"},
		CheckFunc: func(block *parser.Block) []Result {

			directionAttr := block.GetAttribute("direction")
			if directionAttr == nil || directionAttr.Type() != cty.String {
				return nil
			}

			code := AzureOpenInboundNetworkSecurityGroupRule
			checkAttribute := "source_address_prefix"
			if directionAttr.Value().AsString() == "Outbound" {
				code = AzureOpenOutboundNetworkSecurityGroupRule
				checkAttribute = "destination_address_prefix"
			}

			if prefixAttr := block.GetAttribute(checkAttribute); prefixAttr != nil && prefixAttr.Type() == cty.String {
				if strings.HasSuffix(prefixAttr.Value().AsString(), "/0") || prefixAttr.Value().AsString() == "*" {
					return []Result{
						NewResult(
							code,
							fmt.Sprintf(
								"Resource '%s' defines a fully open %s network security group rule.",
								block.Name(),
								strings.ToLower(directionAttr.Value().AsString()),
							),
							prefixAttr.Range(),
						),
					}
				}
			}

			var results []Result

			if prefixesAttr := block.GetAttribute(checkAttribute + "es"); prefixesAttr != nil && prefixesAttr.Value().LengthInt() > 0 {
				for _, prefix := range prefixesAttr.Value().AsValueSlice() {
					if strings.HasSuffix(prefix.AsString(), "/0") || prefix.AsString() == "*" {
						results = append(results,
							NewResult(
								code,
								fmt.Sprintf("Resource '%s' defines a fully open %s security group rule.", block.Name(), prefix.AsString()),
								prefixesAttr.Range(),
							),
						)
					}
				}

			}

			return results
		},
	})
}

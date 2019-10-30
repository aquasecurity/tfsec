package checks

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

const AzureOpenInboundNetworkSecurityGroupRule Code = "AZU001"
const AzureOpenOutboundNetworkSecurityGroupRule Code = "AZU002"


func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_network_security_rule"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {

			directionVal, _, exists := getAttribute(block, ctx, "direction")
			if !exists {
				return nil
			}

			code := AzureOpenInboundNetworkSecurityGroupRule
			checkAttribute := "source_address_prefix"
			if directionVal.AsString() == "Outbound" {
				code = AzureOpenOutboundNetworkSecurityGroupRule
				checkAttribute = "destination_address_prefix"
			}

			if prefix, prefixRange, exists := getAttribute(block, ctx, checkAttribute); exists {
				if strings.HasSuffix(prefix.AsString(), "/0") || prefix.AsString() == "*" {
					return []Result{
						NewResult(
							code,
							fmt.Sprintf(
								"Resource '%s' defines a fully open %s network security group rule.",
								getBlockName(block),
								strings.ToLower(directionVal.AsString()),
							),
							prefixRange,
						),
					}
				}
			}

			var results []Result

			if prefixesVal, prefixesRange, exists := getAttribute(block, ctx, checkAttribute+"es"); exists {
				for _, prefix := range prefixesVal.AsValueSlice() {
					if strings.HasSuffix(prefix.AsString(), "/0") || prefix.AsString() == "*"{
						results = append(results,
							NewResult(
								code,
								fmt.Sprintf("Resource '%s' defines a fully open %s security group rule.", getBlockName(block), prefix.AsString()),
								prefixesRange,
							),
						)
					}
				}

			}

			return results
		},
	})
}

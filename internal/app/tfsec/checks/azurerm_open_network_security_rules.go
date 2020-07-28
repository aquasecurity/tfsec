package checks

import (
	"fmt"
	"strings"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AzureOpenInboundNetworkSecurityGroupRule See https://github.com/liamg/tfsec#included-checks for check info
const AzureOpenInboundNetworkSecurityGroupRule scanner.RuleID = "AZU001"

// AzureOpenOutboundNetworkSecurityGroupRule See https://github.com/liamg/tfsec#included-checks for check info
const AzureOpenOutboundNetworkSecurityGroupRule scanner.RuleID = "AZU002"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AzureOpenInboundNetworkSecurityGroupRule,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_network_security_rule"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			directionAttr := block.GetAttribute("direction")
			if directionAttr == nil || directionAttr.Type() != cty.String || directionAttr.Value().AsString() != "Inbound" {
				return nil
			}

			if prefixAttr := block.GetAttribute("source_address_prefix"); prefixAttr != nil && prefixAttr.Type() == cty.String {
				if strings.HasSuffix(prefixAttr.Value().AsString(), "/0") || prefixAttr.Value().AsString() == "*" {
					if accessAttr := block.GetAttribute("access"); accessAttr != nil && accessAttr.Value().AsString() == "Allow" {
						return []scanner.Result{
							check.NewResultWithValueAnnotation(
								fmt.Sprintf(
									"Resource '%s' defines a fully open %s network security group rule.",
									block.Name(),
									strings.ToLower(directionAttr.Value().AsString()),
								),
								prefixAttr.Range(),
								prefixAttr,
								scanner.SeverityWarning,
							),
						}
					}
				}
			}

			var results []scanner.Result

			if prefixesAttr := block.GetAttribute("source_address_prefixes"); prefixesAttr != nil && prefixesAttr.Value().LengthInt() > 0 {
				for _, prefix := range prefixesAttr.Value().AsValueSlice() {
					if strings.HasSuffix(prefix.AsString(), "/0") || prefix.AsString() == "*" {
						if accessAttr := block.GetAttribute("access"); accessAttr != nil && accessAttr.Value().AsString() == "Allow" {
							results = append(results,
								check.NewResultWithValueAnnotation(
									fmt.Sprintf("Resource '%s' defines a fully open %s security group rule.", block.Name(), prefix.AsString()),
									prefixesAttr.Range(),
									prefixesAttr,
									scanner.SeverityWarning,
								),
							)
						}
					}
				}

			}

			return results
		},
	})

	scanner.RegisterCheck(scanner.Check{
		Code:           AzureOpenOutboundNetworkSecurityGroupRule,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_network_security_rule"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			directionAttr := block.GetAttribute("direction")
			if directionAttr == nil || directionAttr.Type() != cty.String || directionAttr.Value().AsString() != "Outbound" {
				return nil
			}

			if prefixAttr := block.GetAttribute("destination_address_prefix"); prefixAttr != nil && prefixAttr.Type() == cty.String {
				if strings.HasSuffix(prefixAttr.Value().AsString(), "/0") || prefixAttr.Value().AsString() == "*" {
					if accessAttr := block.GetAttribute("access"); accessAttr != nil && accessAttr.Value().AsString() == "Allow" {
						return []scanner.Result{
							check.NewResultWithValueAnnotation(
								fmt.Sprintf(
									"Resource '%s' defines a fully open %s network security group rule.",
									block.Name(),
									strings.ToLower(directionAttr.Value().AsString()),
								),
								prefixAttr.Range(),
								prefixAttr,
								scanner.SeverityWarning,
							),
						}
					}
				}
			}

			var results []scanner.Result

			if prefixesAttr := block.GetAttribute("destination_address_prefixes"); prefixesAttr != nil && prefixesAttr.Value().LengthInt() > 0 {
				for _, prefix := range prefixesAttr.Value().AsValueSlice() {
					if strings.HasSuffix(prefix.AsString(), "/0") || prefix.AsString() == "*" {
						if accessAttr := block.GetAttribute("access"); accessAttr != nil && accessAttr.Value().AsString() == "Allow" {
							results = append(results,
								check.NewResultWithValueAnnotation(
									fmt.Sprintf("Resource '%s' defines a fully open %s security group rule.", block.Name(), prefix.AsString()),
									prefixesAttr.Range(),
									prefixesAttr,
									scanner.SeverityWarning,
								),
							)
						}
					}
				}

			}

			return results
		},
	})
}

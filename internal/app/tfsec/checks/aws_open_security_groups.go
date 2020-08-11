package checks

import (
	"fmt"
	"strings"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSOpenIngressSecurityGroupInlineRule See https://github.com/liamg/tfsec#included-checks for check info
const AWSOpenIngressSecurityGroupInlineRule scanner.RuleID = "AWS008"

// AWSOpenEgressSecurityGroupInlineRule See https://github.com/liamg/tfsec#included-checks for check info
const AWSOpenEgressSecurityGroupInlineRule scanner.RuleID = "AWS009"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSOpenIngressSecurityGroupInlineRule,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			var results []scanner.Result

			for _, directionBlock := range block.GetBlocks("ingress") {
				if cidrBlocksAttr := directionBlock.GetAttribute("cidr_blocks"); cidrBlocksAttr != nil {

					if cidrBlocksAttr.Value().IsNull() || cidrBlocksAttr.Value().LengthInt() == 0 {
						return nil
					}

					for _, cidr := range cidrBlocksAttr.Value().AsValueSlice() {
						if strings.HasSuffix(cidr.AsString(), "/0") {
							results = append(results,
								check.NewResult(
									fmt.Sprintf("Resource '%s' defines a fully open ingress security group.", block.Name()),
									cidrBlocksAttr.Range(),
									scanner.SeverityWarning,
								),
							)
						}
					}
				}
				if cidrBlocksAttr := directionBlock.GetAttribute("ipv6_cidr_blocks"); cidrBlocksAttr != nil {

					if cidrBlocksAttr.Value().IsNull() || cidrBlocksAttr.Value().LengthInt() == 0 {
						return nil
					}

					for _, cidr := range cidrBlocksAttr.Value().AsValueSlice() {
						if strings.HasSuffix(cidr.AsString(), "/0") {
							results = append(results,
								check.NewResult(
									fmt.Sprintf("Resource '%s' defines a fully open ingress security group.", block.Name()),
									cidrBlocksAttr.Range(),
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
		Code:           AWSOpenEgressSecurityGroupInlineRule,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			var results []scanner.Result

			for _, directionBlock := range block.GetBlocks("egress") {
				if cidrBlocksAttr := directionBlock.GetAttribute("cidr_blocks"); cidrBlocksAttr != nil {

					if cidrBlocksAttr.Value().IsNull() || cidrBlocksAttr.Value().LengthInt() == 0 {
						return nil
					}

					for _, cidr := range cidrBlocksAttr.Value().AsValueSlice() {
						if strings.HasSuffix(cidr.AsString(), "/0") {
							results = append(results,
								check.NewResultWithValueAnnotation(
									fmt.Sprintf("Resource '%s' defines a fully open egress security group.", block.Name()),
									cidrBlocksAttr.Range(),
									cidrBlocksAttr,
									scanner.SeverityWarning,
								),
							)
						}
					}
				}
				if cidrBlocksAttr := directionBlock.GetAttribute("ipv6_cidr_blocks"); cidrBlocksAttr != nil {

					if cidrBlocksAttr.Value().IsNull() || cidrBlocksAttr.Value().LengthInt() == 0 {
						return nil
					}

					for _, cidr := range cidrBlocksAttr.Value().AsValueSlice() {
						if strings.HasSuffix(cidr.AsString(), "/0") {
							results = append(results,
								check.NewResultWithValueAnnotation(
									fmt.Sprintf("Resource '%s' defines a fully open egress security group.", block.Name()),
									cidrBlocksAttr.Range(),
									cidrBlocksAttr,
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

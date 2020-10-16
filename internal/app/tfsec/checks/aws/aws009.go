package aws

import (
	"fmt"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// AWSOpenEgressSecurityGroupInlineRule See https://github.com/tfsec/tfsec#included-checks for check info
const AWSOpenEgressSecurityGroupInlineRule scanner.RuleID = "AWS009"
const AWSOpenEgressSecurityGroupInlineRuleDescription scanner.RuleSummary = "An inline egress security group rule allows traffic to `/0`."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSOpenEgressSecurityGroupInlineRule,
		Documentation: scanner.CheckDocumentation{
			Summary: AWSOpenEgressSecurityGroupInlineRuleDescription,
		},
		Provider:       scanner.AWSProvider,
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

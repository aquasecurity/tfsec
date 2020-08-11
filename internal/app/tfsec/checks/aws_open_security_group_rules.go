package checks

import (
	"fmt"
	"strings"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSOpenIngressSecurityGroupRule See https://github.com/liamg/tfsec#included-checks for check info
const AWSOpenIngressSecurityGroupRule scanner.RuleID = "AWS006"

// AWSOpenEgressSecurityGroupRule See https://github.com/liamg/tfsec#included-checks for check info
const AWSOpenEgressSecurityGroupRule scanner.RuleID = "AWS007"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSOpenIngressSecurityGroupRule,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group_rule"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			typeAttr := block.GetAttribute("type")
			if typeAttr == nil || typeAttr.Type() != cty.String {
				return nil
			}

			if typeAttr.Value().AsString() != "ingress" {
				return nil
			}

			if cidrBlocksAttr := block.GetAttribute("cidr_blocks"); cidrBlocksAttr != nil {

				if cidrBlocksAttr.Value().IsNull() || cidrBlocksAttr.Value().LengthInt() == 0 {
					return nil
				}

				for _, cidr := range cidrBlocksAttr.Value().AsValueSlice() {
					if strings.HasSuffix(cidr.AsString(), "/0") {
						return []scanner.Result{
							check.NewResult(
								fmt.Sprintf("Resource '%s' defines a fully open ingress security group rule.", block.Name()),
								cidrBlocksAttr.Range(),
								scanner.SeverityWarning,
							),
						}
					}
				}

			}

			if ipv6CidrBlocksAttr := block.GetAttribute("ipv6_cidr_blocks"); ipv6CidrBlocksAttr != nil {

				if ipv6CidrBlocksAttr.Value().IsNull() || ipv6CidrBlocksAttr.Value().LengthInt() == 0 {
					return nil
				}

				for _, cidr := range ipv6CidrBlocksAttr.Value().AsValueSlice() {
					if strings.HasSuffix(cidr.AsString(), "/0") {
						return []scanner.Result{
							check.NewResultWithValueAnnotation(
								fmt.Sprintf("Resource '%s' defines a fully open egress security group rule.", block.Name()),
								ipv6CidrBlocksAttr.Range(),
								ipv6CidrBlocksAttr,
								scanner.SeverityWarning,
							),
						}
					}
				}

			}

			return nil
		},
	})

	scanner.RegisterCheck(scanner.Check{
		Code:           AWSOpenEgressSecurityGroupRule,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group_rule"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			typeAttr := block.GetAttribute("type")
			if typeAttr == nil || typeAttr.Type() != cty.String {
				return nil
			}

			if typeAttr.Value().AsString() != "egress" {
				return nil
			}

			if cidrBlocksAttr := block.GetAttribute("cidr_blocks"); cidrBlocksAttr != nil {

				if cidrBlocksAttr.Value().IsNull() || cidrBlocksAttr.Value().LengthInt() == 0 {
					return nil
				}

				for _, cidr := range cidrBlocksAttr.Value().AsValueSlice() {
					if strings.HasSuffix(cidr.AsString(), "/0") {
						return []scanner.Result{
							check.NewResultWithValueAnnotation(
								fmt.Sprintf("Resource '%s' defines a fully open egress security group rule.", block.Name()),
								cidrBlocksAttr.Range(),
								cidrBlocksAttr,
								scanner.SeverityWarning,
							),
						}
					}
				}

			}

			if ipv6CidrBlocksAttr := block.GetAttribute("ipv6_cidr_blocks"); ipv6CidrBlocksAttr != nil {

				if ipv6CidrBlocksAttr.Value().IsNull() || ipv6CidrBlocksAttr.Value().LengthInt() == 0 {
					return nil
				}

				for _, cidr := range ipv6CidrBlocksAttr.Value().AsValueSlice() {
					if strings.HasSuffix(cidr.AsString(), "/0") {
						return []scanner.Result{
							check.NewResultWithValueAnnotation(
								fmt.Sprintf("Resource '%s' defines a fully open egress security group rule.", block.Name()),
								ipv6CidrBlocksAttr.Range(),
								ipv6CidrBlocksAttr,
								scanner.SeverityWarning,
							),
						}
					}
				}

			}

			return nil
		},
	})
}

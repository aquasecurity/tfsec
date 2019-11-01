package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSOutdatedSSLPolicy See https://github.com/liamg/tfsec#included-checks for check info
const AWSOutdatedSSLPolicy Code = "AWS010"

var outdatedSSLPolicies = []string{
	"ELBSecurityPolicy-2015-05",
	"ELBSecurityPolicy-TLS-1-0-2015-04",
	"ELBSecurityPolicy-2016-08",
	"ELBSecurityPolicy-TLS-1-1-2017-01",
}

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_lb_listener", "aws_alb_listener"},
		CheckFunc: func(block *parser.Block) []Result {

			if sslPolicyAttr := block.GetAttribute("ssl_policy"); sslPolicyAttr != nil && sslPolicyAttr.Type() == cty.String {
				for _, policy := range outdatedSSLPolicies {
					if policy == sslPolicyAttr.Value().AsString() {
						return []Result{
							NewResult(
								AWSOutdatedSSLPolicy,
								fmt.Sprintf("Resource '%s' is using an outdated SSL policy.", block.Name()),
								sslPolicyAttr.Range(),
							),
						}
					}
				}
			}

			return nil
		},
	})
}

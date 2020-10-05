package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSOutdatedSSLPolicy See https://github.com/tfsec/tfsec#included-checks for check info
const AWSOutdatedSSLPolicy scanner.RuleID = "AWS010"
const AWSOutdatedSSLPolicyDescription scanner.RuleDescription = "An outdated SSL policy is in use by a load balancer."

var outdatedSSLPolicies = []string{
	"ELBSecurityPolicy-2015-05",
	"ELBSecurityPolicy-TLS-1-0-2015-04",
	"ELBSecurityPolicy-2016-08",
	"ELBSecurityPolicy-TLS-1-1-2017-01",
}

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSOutdatedSSLPolicy,
		Description:    AWSOutdatedSSLPolicyDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_lb_listener", "aws_alb_listener"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if sslPolicyAttr := block.GetAttribute("ssl_policy"); sslPolicyAttr != nil && sslPolicyAttr.Type() == cty.String {
				for _, policy := range outdatedSSLPolicies {
					if policy == sslPolicyAttr.Value().AsString() {
						return []scanner.Result{
							check.NewResultWithValueAnnotation(
								fmt.Sprintf("Resource '%s' is using an outdated SSL policy.", block.Name()),
								sslPolicyAttr.Range(),
								sslPolicyAttr,
								scanner.SeverityError,
							),
						}
					}
				}
			}

			return nil
		},
	})
}

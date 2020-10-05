package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"
)

// AWSApiGatewayDomainNameOutdatedSecurityPolicy See https://github.com/tfsec/tfsec#included-checks for check info
const AWSApiGatewayDomainNameOutdatedSecurityPolicy scanner.RuleID = "AWS025"
const AWSApiGatewayDomainNameOutdatedSecurityPolicyDescription scanner.RuleDescription = "API Gateway domain name uses outdated SSL/TLS protocols."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSApiGatewayDomainNameOutdatedSecurityPolicy,
		Description:    AWSApiGatewayDomainNameOutdatedSecurityPolicyDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_api_gateway_domain_name"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			securityPolicyAttr := block.GetAttribute("security_policy")
			if securityPolicyAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should include security_policy (defauls to outdated SSL/TLS policy).", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			if securityPolicyAttr.Type() == cty.String && securityPolicyAttr.Value().AsString() != "TLS_1_2" {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines outdated SSL/TLS policies (not using TLS_1_2).", block.Name()),
						securityPolicyAttr.Range(),
						securityPolicyAttr,
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}

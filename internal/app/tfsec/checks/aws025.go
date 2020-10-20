package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSApiGatewayDomainNameOutdatedSecurityPolicy scanner.RuleCode = "AWS025"
const AWSApiGatewayDomainNameOutdatedSecurityPolicyDescription scanner.RuleSummary = "API Gateway domain name uses outdated SSL/TLS protocols."
const AWSApiGatewayDomainNameOutdatedSecurityPolicyExplanation = `
You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
`
const AWSApiGatewayDomainNameOutdatedSecurityPolicyBadExample = `
resource "aws_api_gateway_domain_name" "my-resource" {
	security_policy = "TLS_1_0"
}
`
const AWSApiGatewayDomainNameOutdatedSecurityPolicyGoodExample = `
resource "aws_api_gateway_domain_name" "my-resource" {
	security_policy = "TLS_1_2"
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSApiGatewayDomainNameOutdatedSecurityPolicy,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSApiGatewayDomainNameOutdatedSecurityPolicyDescription,
			Explanation: AWSApiGatewayDomainNameOutdatedSecurityPolicyExplanation,
			BadExample:  AWSApiGatewayDomainNameOutdatedSecurityPolicyBadExample,
			GoodExample: AWSApiGatewayDomainNameOutdatedSecurityPolicyGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_api_gateway_domain_name"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			securityPolicyAttr := block.GetAttribute("security_policy")
			if securityPolicyAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should include security_policy (defauls to outdated SSL/TLS policy).", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			if securityPolicyAttr.Type() == cty.String && securityPolicyAttr.Value().AsString() != "TLS_1_2" {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines outdated SSL/TLS policies (not using TLS_1_2).", block.FullName()),
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

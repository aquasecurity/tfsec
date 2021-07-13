package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSApiGatewayDomainNameOutdatedSecurityPolicy = "AWS025"
const AWSApiGatewayDomainNameOutdatedSecurityPolicyDescription = "API Gateway domain name uses outdated SSL/TLS protocols."
const AWSApiGatewayDomainNameOutdatedSecurityPolicyImpact = "Outdated SSL policies increase exposure to known vulnerabilities"
const AWSApiGatewayDomainNameOutdatedSecurityPolicyResolution = "Use the most modern TLS/SSL policies available"
const AWSApiGatewayDomainNameOutdatedSecurityPolicyExplanation = `
You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
`
const AWSApiGatewayDomainNameOutdatedSecurityPolicyBadExample = `
resource "aws_api_gateway_domain_name" "bad_example" {
	security_policy = "TLS_1_0"
}
`
const AWSApiGatewayDomainNameOutdatedSecurityPolicyGoodExample = `
resource "aws_api_gateway_domain_name" "good_example" {
	security_policy = "TLS_1_2"
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSApiGatewayDomainNameOutdatedSecurityPolicy,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSApiGatewayDomainNameOutdatedSecurityPolicyDescription,
			Impact:      AWSApiGatewayDomainNameOutdatedSecurityPolicyImpact,
			Resolution:  AWSApiGatewayDomainNameOutdatedSecurityPolicyResolution,
			Explanation: AWSApiGatewayDomainNameOutdatedSecurityPolicyExplanation,
			BadExample:  AWSApiGatewayDomainNameOutdatedSecurityPolicyBadExample,
			GoodExample: AWSApiGatewayDomainNameOutdatedSecurityPolicyGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name#security_policy",
				"https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_api_gateway_domain_name"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			securityPolicyAttr := resourceBlock.GetAttribute("security_policy")
			if securityPolicyAttr == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' should include security_policy (defaults to outdated SSL/TLS policy).", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			if securityPolicyAttr.Type() == cty.String && securityPolicyAttr.Value().AsString() != "TLS_1_2" {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines outdated SSL/TLS policies (not using TLS_1_2).", resourceBlock.FullName())).
						WithRange(securityPolicyAttr.Range()).
						WithAttributeAnnotation(securityPolicyAttr),
				)
			}

		},
	})
}

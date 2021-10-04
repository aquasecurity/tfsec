package apigateway

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS025",
		Service:   "api-gateway",
		ShortCode: "use-secure-tls-policy",
		Documentation: rule.RuleDocumentation{
			Summary:    "API Gateway domain name uses outdated SSL/TLS protocols.",
			Impact:     "Outdated SSL policies increase exposure to known vulnerabilities",
			Resolution: "Use the most modern TLS/SSL policies available",
			Explanation: `
You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
`,
			BadExample: []string{`
resource "aws_api_gateway_domain_name" "bad_example" {
	security_policy = "TLS_1_0"
}
`},
			GoodExample: []string{`
resource "aws_api_gateway_domain_name" "good_example" {
	security_policy = "TLS_1_2"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name#security_policy",
				"https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_api_gateway_domain_name"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {

			securityPolicyAttr := resourceBlock.GetAttribute("security_policy")
			if securityPolicyAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' should include security_policy (defaults to outdated SSL/TLS policy).", resourceBlock.FullName())
				return
			}

			if securityPolicyAttr.NotEqual("TLS_1_2") {
				set.AddResult().
					WithDescription("Resource '%s' defines outdated SSL/TLS policies (not using TLS_1_2).", resourceBlock.FullName()).
					WithAttribute(securityPolicyAttr)
			}
		},
	})
}

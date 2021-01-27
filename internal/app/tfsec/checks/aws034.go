package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSOutdatedTLSPolicyElasticsearchDomainEndpoint scanner.RuleCode = "AWS034"
const AWSOutdatedTLSPolicyElasticsearchDomainEndpointDescription scanner.RuleSummary = "Elasticsearch domain endpoint is using outdated TLS policy."
const AWSOutdatedTLSPolicyElasticsearchDomainEndpointExplanation = `
You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
`
const AWSOutdatedTLSPolicyElasticsearchDomainEndpointBadExample = `
resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
  domain_name = "domain-foo"

  domain_endpoint_options {
    enforce_https = true
    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
  }
}
`
const AWSOutdatedTLSPolicyElasticsearchDomainEndpointGoodExample = `
resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
  domain_name = "domain-foo"

  domain_endpoint_options {
    enforce_https = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSOutdatedTLSPolicyElasticsearchDomainEndpoint,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSOutdatedTLSPolicyElasticsearchDomainEndpointDescription,
			Explanation: AWSOutdatedTLSPolicyElasticsearchDomainEndpointExplanation,
			BadExample:  AWSOutdatedTLSPolicyElasticsearchDomainEndpointBadExample,
			GoodExample: AWSOutdatedTLSPolicyElasticsearchDomainEndpointGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			endpointBlock := block.GetBlock("domain_endpoint_options")
			if endpointBlock == nil {
				// Check AWS033 covers this case.
				return nil
			}

			tlsPolicyAttr := endpointBlock.GetAttribute("tls_security_policy")
			if tlsPolicyAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with an outdated TLS policy (defaults to Policy-Min-TLS-1-0-2019-07).", block.FullName()),
						endpointBlock.Range(),
						scanner.SeverityError,
					),
				}

				return nil
			}

			if tlsPolicyAttr.Value().Equals(cty.StringVal("Policy-Min-TLS-1-0-2019-07")).True() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with an outdated TLS policy (set to Policy-Min-TLS-1-0-2019-07).", block.FullName()),
						tlsPolicyAttr.Range(),
						tlsPolicyAttr,
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}

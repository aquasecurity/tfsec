package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSOutdatedTLSPolicyElasticsearchDomainEndpoint See
// https://github.com/tfsec/tfsec#included-checks for check info
const AWSOutdatedTLSPolicyElasticsearchDomainEndpoint scanner.RuleID = "AWS034"
const AWSOutdatedTLSPolicyElasticsearchDomainEndpointDescription scanner.RuleDescription = "Elasticsearch domain endpoint is using outdated TLS policy."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSOutdatedTLSPolicyElasticsearchDomainEndpoint,
		Description:    AWSOutdatedTLSPolicyElasticsearchDomainEndpointDescription,
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
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with an outdated TLS policy (defaults to Policy-Min-TLS-1-0-2019-07).", block.Name()),
						endpointBlock.Range(),
						scanner.SeverityError,
					),
				}

				return nil
			}

			if tlsPolicyAttr.Value().Equals(cty.StringVal("Policy-Min-TLS-1-0-2019-07")).True() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with an outdated TLS policy (set to Policy-Min-TLS-1-0-2019-07).", block.Name()),
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

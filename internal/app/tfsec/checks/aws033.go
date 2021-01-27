package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSUnenforcedHTTPSElasticsearchDomainEndpoint See
// https://github.com/tfsec/tfsec#included-checks for check info
const AWSUnenforcedHTTPSElasticsearchDomainEndpoint scanner.RuleCode = "AWS033"
const AWSUnenforcedHTTPSElasticsearchDomainEndpointDescription scanner.RuleSummary = "Elasticsearch doesn't enforce HTTPS traffic."
const AWSUnenforcedHTTPSElasticsearchDomainEndpointExplanation = `
Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.
`
const AWSUnenforcedHTTPSElasticsearchDomainEndpointBadExample = `
resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
  domain_name = "domain-foo"

  domain_endpoint_options {
    enforce_https = false
  }
}
`
const AWSUnenforcedHTTPSElasticsearchDomainEndpointGoodExample = `
resource "aws_elasticsearch_domain" "my_elasticsearch_domain" {
  domain_name = "domain-foo"

  domain_endpoint_options {
    enforce_https = true
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSUnenforcedHTTPSElasticsearchDomainEndpoint,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSUnenforcedHTTPSElasticsearchDomainEndpointDescription,
			Explanation: AWSUnenforcedHTTPSElasticsearchDomainEndpointExplanation,
			BadExample:  AWSUnenforcedHTTPSElasticsearchDomainEndpointBadExample,
			GoodExample: AWSUnenforcedHTTPSElasticsearchDomainEndpointGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			endpointBlock := block.GetBlock("domain_endpoint_options")
			if endpointBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with plaintext traffic (missing domain_endpoint_options block).", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			enforceHTTPSAttr := endpointBlock.GetAttribute("enforce_https")
			if enforceHTTPSAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with plaintext traffic (missing enforce_https attribute).", block.FullName()),
						endpointBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			isTrueBool := enforceHTTPSAttr.Type() == cty.Bool && enforceHTTPSAttr.Value().True()
			isTrueString := enforceHTTPSAttr.Type() == cty.String &&
				enforceHTTPSAttr.Value().Equals(cty.StringVal("true")).True()
			enforcedHTTPS := isTrueBool || isTrueString
			if !enforcedHTTPS {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an Elasticsearch domain with plaintext traffic (enabled attribute set to false).", block.FullName()),
						endpointBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}

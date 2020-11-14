package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSElasticSearchDomainEnforceHTTPS scanner.RuleCode = "AWS054"
const AWSElasticSearchDomainEnforceHTTPSDescription scanner.RuleSummary = "ElasticSearch domains should enforce HTTPS"
const AWSElasticSearchDomainEnforceHTTPSExplanation = `
Amazon Elasticsearch Service now lets you configure your domains to require that all traffic be submitted over HTTPS so that you can ensure that communications between your clients and your domain are encrypted. 

You can also configure the minimum required TLS version to accept. 

This option is a useful additional security control to ensure your clients are not misconfigured.
`
const AWSElasticSearchDomainEnforceHTTPSBadExample = `
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  domain_endpoint_options {
    enforce_https = false
  }
}
`
const AWSElasticSearchDomainEnforceHTTPSGoodExample = `
resource "aws_elasticsearch_domain" "good_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  domain_endpoint_options {
    enforce_https = true
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSElasticSearchDomainEnforceHTTPS,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSElasticSearchDomainEnforceHTTPSDescription,
			Explanation: AWSElasticSearchDomainEnforceHTTPSExplanation,
			BadExample:  AWSElasticSearchDomainEnforceHTTPSBadExample,
			GoodExample: AWSElasticSearchDomainEnforceHTTPSGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#enforce_https",
				"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-domainendpointoptions.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.HasChild("domain_endpoint_options") {
				endpointOptions := block.GetBlock("domain_endpoint_options")
				enforceHttps := endpointOptions.GetAttribute("enforce_https")
				if enforceHttps != nil && enforceHttps.IsFalse() {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' explicitly turns off enforcing https on the ElasticSearch domain.", block.FullName()),
							block.Range(),
							scanner.SeverityError,
						),
					}
				}
			}

			return nil
		},
	})
}

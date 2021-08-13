package elasticsearch

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
		LegacyID:  "AWS033",
		Service:   "elastic-search",
		ShortCode: "enforce-https",
		Documentation: rule.RuleDocumentation{
			Summary:    "Elasticsearch doesn't enforce HTTPS traffic.",
			Impact:     "HTTP traffic can be intercepted and the contents read",
			Resolution: "Enforce the use of HTTPS for ElasticSearch",
			Explanation: `
Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.
`,
			BadExample: []string{`
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name = "domain-foo"

  domain_endpoint_options {
    enforce_https = false
  }
}
`},
			GoodExample: []string{`
resource "aws_elasticsearch_domain" "good_example" {
  domain_name = "domain-foo"

  domain_endpoint_options {
    enforce_https = true
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#enforce_https",
				"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticsearch_domain"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context block.Module) {

			endpointBlock := resourceBlock.GetBlock("domain_endpoint_options")
			if endpointBlock.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines an Elasticsearch domain with plaintext traffic (missing domain_endpoint_options block).", resourceBlock.FullName())
				return
			}

			enforceHTTPSAttr := endpointBlock.GetAttribute("enforce_https")
			if enforceHTTPSAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines an Elasticsearch domain with plaintext traffic (missing enforce_https attribute).", resourceBlock.FullName())
				return
			}

			if enforceHTTPSAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' defines an Elasticsearch domain with plaintext traffic (enabled attribute set to false).", resourceBlock.FullName())
			}

		},
	})
}

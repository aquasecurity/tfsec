package elasticsearch

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/elasticsearch"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS034",
		BadExample: []string{`
 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name = "domain-foo"
 
   domain_endpoint_options {
     enforce_https = true
     tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
   }
 }
 `},
		GoodExample: []string{`
 resource "aws_elasticsearch_domain" "good_example" {
   domain_name = "domain-foo"
 
   domain_endpoint_options {
     enforce_https = true
     tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#tls_security_policy",
			"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		Base:           elasticsearch.CheckUseSecureTlsPolicy,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			endpointBlock := resourceBlock.GetBlock("domain_endpoint_options")
			if endpointBlock.IsNil() {
				return
			}

			tlsPolicyAttr := endpointBlock.GetAttribute("tls_security_policy")
			if tlsPolicyAttr.IsNil() {
				results.Add("Resource defines an Elasticsearch domain with an outdated TLS policy (defaults to Policy-Min-TLS-1-0-2019-07).", endpointBlock)
				return
			}

			if tlsPolicyAttr.Equals("Policy-Min-TLS-1-0-2019-07") {
				results.Add("Resource defines an Elasticsearch domain with an outdated TLS policy (set to Policy-Min-TLS-1-0-2019-07).", tlsPolicyAttr)
			}

			return results
		},
	})
}

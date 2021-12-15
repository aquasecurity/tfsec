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
		LegacyID: "AWS033",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		Base:           elasticsearch.CheckEnforceHttps,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			endpointBlock := resourceBlock.GetBlock("domain_endpoint_options")
			if endpointBlock.IsNil() {
				results.Add("Resource defines an Elasticsearch domain with plaintext traffic (missing domain_endpoint_options block).", resourceBlock)
				return
			}

			enforceHTTPSAttr := endpointBlock.GetAttribute("enforce_https")
			if enforceHTTPSAttr.IsNil() {
				results.Add("Resource defines an Elasticsearch domain with plaintext traffic (missing enforce_https attribute).", endpointBlock)
				return
			}

			if enforceHTTPSAttr.IsFalse() {
				results.Add("Resource defines an Elasticsearch domain with plaintext traffic (enabled attribute set to false).", enforceHTTPSAttr)
			}

			return results
		},
	})
}

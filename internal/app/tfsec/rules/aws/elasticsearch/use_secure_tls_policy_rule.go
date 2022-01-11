package elasticsearch

import (
	"github.com/aquasecurity/defsec/rules/aws/elasticsearch"
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		Base:           elasticsearch.CheckUseSecureTlsPolicy,
	})
}

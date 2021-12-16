package compute

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "google_compute_ssl_policy" "bad_example" {
   name    = "production-ssl-policy"
   profile = "MODERN"
   min_tls_version = "TLS_1_1"
 }
 
 `},
		GoodExample: []string{`
 resource "google_compute_ssl_policy" "good_example" {
   name    = "production-ssl-policy"
   profile = "MODERN"
   min_tls_version = "TLS_1_2"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_ssl_policy#min_tls_version",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"google_compute_ssl_policy",
		},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if minTlsVersionAttr := resourceBlock.GetAttribute("min_tls_version"); minTlsVersionAttr.IsNil() { // alert on use of default value
				results.Add("Resource uses default value for min_tls_version", ?)
			} else if minTlsVersionAttr.NotEqual("TLS_1_2") {
				results.Add("Resource does not have min_tls_version set to TLS_1_2", minTlsVersionAttr)
			}
			return results
		},
	})
}

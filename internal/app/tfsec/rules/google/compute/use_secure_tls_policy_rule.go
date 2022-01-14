package compute

import (
	"github.com/aquasecurity/defsec/rules/google/compute"
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
		Base: compute.CheckUseSecureTlsPolicy,
	})
}

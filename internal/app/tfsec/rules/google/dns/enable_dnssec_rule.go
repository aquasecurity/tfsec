package dns

import (
	"github.com/aquasecurity/defsec/rules/google/dns"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "google_dns_managed_zone" "bad_example" {
   name        = "example-zone"
   dns_name    = "example-${random_id.rnd.hex}.com."
   description = "Example DNS zone"
   labels = {
     foo = "bar"
   }
   dnssec_config {
     state = "off"
   }
 }
 
 resource "random_id" "rnd" {
   byte_length = 4
 }
 `},
		GoodExample: []string{`
 resource "google_dns_managed_zone" "good_example" {
   name        = "example-zone"
   dns_name    = "example-${random_id.rnd.hex}.com."
   description = "Example DNS zone"
   labels = {
     foo = "bar"
   }
   dnssec_config {
     state = "on"
   }
 }
 
 resource "random_id" "rnd" {
   byte_length = 4
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/dns_managed_zone#state",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"google_dns_managed_zone",
		},
		Base: dns.CheckEnableDnssec,
	})
}

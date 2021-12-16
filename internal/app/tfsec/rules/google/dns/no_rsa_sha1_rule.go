package dns

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "google_dns_managed_zone" "foo" {
 	name     = "foobar"
 	dns_name = "foo.bar."
 	
 	dnssec_config {
 		state         = "on"
 		non_existence = "nsec3"
 	}
 }
 	
 data "google_dns_keys" "foo_dns_keys" {
 	managed_zone = google_dns_managed_zone.foo.id
 	zone_signing_keys {
 		algorithm = "rsasha1"
 	}
 }
 	
 output "foo_dns_ds_record" {
 	description = "DS record of the foo subdomain."
 	value       = data.google_dns_keys.foo_dns_keys.key_signing_keys[0].ds_record
 }
 `},
		GoodExample: []string{`
 resource "google_dns_managed_zone" "foo" {
 	name     = "foobar"
 	dns_name = "foo.bar."
 	
 	dnssec_config {
 		state         = "on"
 		non_existence = "nsec3"
 	}
 }
 	
 data "google_dns_keys" "foo_dns_keys" {
 	managed_zone = google_dns_managed_zone.foo.id
 	zone_signing_keys {
 		algorithm = "rsasha512"
 	}
 }
 	
 output "foo_dns_ds_record" {
 	description = "DS record of the foo subdomain."
 	value       = data.google_dns_keys.foo_dns_keys.key_signing_keys[0].ds_record
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/dns_managed_zone#algorithm",
		},
		RequiredTypes: []string{
			"data",
		},
		RequiredLabels: []string{
			"google_dns_keys",
		},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if algorithmAttr := resourceBlock.GetBlock("zone_signing_keys").GetAttribute("algorithm"); algorithmAttr.Equals("rsasha1") {
				results.Add("Data '%s' has zone_signing_keys.algorithm set to rsasha1", algorithmAttr)
			}
			if algorithmAttr := resourceBlock.GetBlock("key_signing_keys").GetAttribute("algorithm"); algorithmAttr.Equals("rsasha1") {
				results.Add("Data '%s' has key_signing_keys.algorithm set to rsasha1", algorithmAttr)
			}
			return results
		},
	})
}

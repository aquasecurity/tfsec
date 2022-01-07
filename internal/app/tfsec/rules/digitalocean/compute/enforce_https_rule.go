package compute

import (
	"github.com/aquasecurity/defsec/rules/digitalocean/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "DIG004",
		BadExample: []string{`
 resource "digitalocean_loadbalancer" "bad_example" {
   name   = "bad_example-1"
   region = "nyc3"
 
   forwarding_rule {
     entry_port     = 80
     entry_protocol = "http"
 
     target_port     = 80
     target_protocol = "http"
   }
 
   droplet_ids = [digitalocean_droplet.web.id]
 }
 `},
		GoodExample: []string{`
 resource "digitalocean_loadbalancer" "bad_example" {
   name   = "bad_example-1"
   region = "nyc3"
   
   forwarding_rule {
 	entry_port     = 443
 	entry_protocol = "https"
   
 	target_port     = 443
 	target_protocol = "https"
   }
   
   droplet_ids = [digitalocean_droplet.web.id]
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/loadbalancer",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"digitalocean_loadbalancer"},
		Base:           compute.CheckEnforceHttps,
	})
}

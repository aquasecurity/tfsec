package compute

import (
	"github.com/aquasecurity/defsec/rules/digitalocean/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "DIG003",
		BadExample: []string{`
 resource "digitalocean_droplet" "good_example" {
 	image    = "ubuntu-18-04-x64"
 	name     = "web-1"
 	region   = "nyc2"
 	size     = "s-1vcpu-1gb"
  }
 `},
		GoodExample: []string{`
 data "digitalocean_ssh_key" "terraform" {
 	name = "myKey"
   }
   
 resource "digitalocean_droplet" "good_example" {
 	image    = "ubuntu-18-04-x64"
 	name     = "web-1"
 	region   = "nyc2"
 	size     = "s-1vcpu-1gb"
 	ssh_keys = [ data.digitalocean_ssh_key.myKey.id ]
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/droplet#ssh_keys",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"digitalocean_droplet"},
		Base:           compute.CheckUseSshKeys,
	})
}

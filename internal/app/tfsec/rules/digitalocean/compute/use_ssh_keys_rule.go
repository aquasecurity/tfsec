package compute

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/digitalocean/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://www.digitalocean.com/community/tutorials/understanding-the-ssh-encryption-and-connection-process",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"digitalocean_droplet"},
		Base:           compute.CheckUseSshKeys,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("ssh_keys") {
				results.Add("Resource does not define ssh_keys", resourceBlock)
				return
			}
			sshKeysAttr := resourceBlock.GetAttribute("ssh_keys")
			if sshKeysAttr.IsEmpty() {
				results.Add("Resource has ssh_key specified but is empty.", sshKeysAttr)
			}
			return results
		},
	})
}

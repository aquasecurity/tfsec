package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

const DIGDropletHasNoSSHKeysAssigned = "DIG003"
const DIGDropletHasNoSSHKeysAssignedDescription = "SSH Keys are the preferred way to connect to your droplet, no keys are supplied"
const DIGDropletHasNoSSHKeysAssignedImpact = "Logging in with username and password is easier to compromise"
const DIGDropletHasNoSSHKeysAssignedResolution = "Use ssh keys for login"
const DIGDropletHasNoSSHKeysAssignedExplanation = `
When working with a server, you’ll likely spend most of your time in a terminal session connected to your server through SSH. A more secure alternative to password-based logins, SSH keys use encryption to provide a secure way of logging into your server and are recommended for all users.
`
const DIGDropletHasNoSSHKeysAssignedBadExample = `
resource "digitalocean_droplet" "good_example" {
	image    = "ubuntu-18-04-x64"
	name     = "web-1"
	region   = "nyc2"
	size     = "s-1vcpu-1gb"
 }
`
const DIGDropletHasNoSSHKeysAssignedGoodExample = `
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
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: DIGDropletHasNoSSHKeysAssigned,
		Documentation: rule.RuleDocumentation{
			Summary:     DIGDropletHasNoSSHKeysAssignedDescription,
			Explanation: DIGDropletHasNoSSHKeysAssignedExplanation,
			Impact:      DIGDropletHasNoSSHKeysAssignedImpact,
			Resolution:  DIGDropletHasNoSSHKeysAssignedResolution,
			BadExample:  DIGDropletHasNoSSHKeysAssignedBadExample,
			GoodExample: DIGDropletHasNoSSHKeysAssignedGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/droplet#ssh_keys",
				"https://www.digitalocean.com/community/tutorials/understanding-the-ssh-encryption-and-connection-process",
			},
		},
		Provider:        provider.DigitalOceanProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"digitalocean_droplet"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("ssh_keys") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not define ssh_keys", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}
			sshKeysAttr := resourceBlock.GetAttribute("ssh_keys")
			if sshKeysAttr.IsEmpty() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' has ssh_key specified but is empty.", resourceBlock.FullName())).
						WithRange(sshKeysAttr.Range()).
						WithAttributeAnnotation(sshKeysAttr),
				)
			}
		},
	})
}

package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_DIGDropletHasNoSSHKeysAssigned(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "droplet with no ssh_keys fails check",
			source: `
resource "digitalocean_droplet" "bad_example" {
  image  = "ubuntu-18-04-x64"
  name   = "web-1"
  region = "nyc2"
  size   = "s-1vcpu-1gb"
}
`,
			mustIncludeResultCode: rules.DIGDropletHasNoSSHKeysAssigned,
		},
		{
			name: "droplet with ssh keys defined but empty fails check",
			source: `
resource "digitalocean_droplet" "bad_example" {
  image    = "ubuntu-18-04-x64"
  name     = "web-1"
  region   = "nyc2"
  size     = "s-1vcpu-1gb"
  ssh_heys = []
}
`,
			mustIncludeResultCode: rules.DIGDropletHasNoSSHKeysAssigned,
		},
		{
			name: "TODO: add test name",
			source: `
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
`,
			mustExcludeResultCode: rules.DIGDropletHasNoSSHKeysAssigned,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

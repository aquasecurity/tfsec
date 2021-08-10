package compute

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_DIGFirewallHasOpenInboundAccess(t *testing.T) {
	expectedCode := "digitalocean-compute-no-public-ingress"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "digital ocean firewall with open source addresses fails check",
			source: `
resource "digitalocean_firewall" "bad_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	inbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  source_addresses = ["0.0.0.0/0", "::/0"]
	}
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "digital ocean firewall with open ipv6 source addresses fails check",
			source: `
resource "digitalocean_firewall" "bad_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	inbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  source_addresses = ["::/0"]
	}
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "digital ocean firewall with open ipv4 source addresses fails check",
			source: `
resource "digitalocean_firewall" "bad_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	inbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  source_addresses = ["0.0.0.0/0"]
	}
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "digital ocean firewall with good source addresses passes check",
			source: `
resource "digitalocean_firewall" "good_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	inbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  source_addresses = ["192.168.1.0/24", "2002:1:2::/48"]
	}
}

`,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

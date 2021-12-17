package compute

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_DIGLoadBalancerWithPlainHTTP(t *testing.T) {
	expectedCode := "digitalocean-compute-enforce-https"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Load balancer with http entry protocol fails check",
			source: `
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
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Load blanacer with non plain http passes check (https)",
			source: `
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
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "Load blanacer with non plain http passes check (http2)",
			source: `
 resource "digitalocean_loadbalancer" "bad_example" {
   name   = "bad_example-1"
   region = "nyc3"
   
   forwarding_rule {
 	entry_port     = 443
 	entry_protocol = "http2"
   
 	target_port     = 443
 	target_protocol = "https"
   }
   
   droplet_ids = [digitalocean_droplet.web.id]
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "Load blanacer with non plain http passes check (tcp)",
			source: `
 resource "digitalocean_loadbalancer" "bad_example" {
   name   = "bad_example-1"
   region = "nyc3"
   
   forwarding_rule {
 	entry_port     = 3128
 	entry_protocol = "tcp"
   
 	target_port     = 3128
 	target_protocol = "tcpv"
   }
   
   droplet_ids = [digitalocean_droplet.web.id]
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

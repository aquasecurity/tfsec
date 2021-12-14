package compute
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_OpenStackNoPlaintextPassword(t *testing.T) {
 	expectedCode := "openstack-compute-no-plaintext-password"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "compute instance with a plain text password fails check",
 			source: `
 resource "openstack_compute_instance_v2" "bad_example" {
   name            = "basic"
   image_id        = "ad091b52-742f-469e-8f3c-fd81cadf0743"
   flavor_id       = "3"
   admin_pass      = "N0tSoS3cretP4ssw0rd"
   security_groups = ["default"]
   user_data       = "#cloud-config\nhostname: instance_1.example.com\nfqdn: instance_1.example.com"
 
   network {
     name = "my_network"
   }
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "compute instance with no admin_pass passes check",
 			source: `
 resource "openstack_compute_instance_v2" "good_example" {
   name            = "basic"
   image_id        = "ad091b52-742f-469e-8f3c-fd81cadf0743"
   flavor_id       = "3"
   key_pair        = "my_key_pair_name"
   security_groups = ["default"]
   user_data       = "#cloud-config\nhostname: instance_1.example.com\nfqdn: instance_1.example.com"
 
   network {
     name = "my_network"
   }
 }
 `,
 			mustExcludeResultCode: expectedCode,
 		},
 
 		{
 			name: "compute instance with no admin_pass passes check",
 			source: `
 variable "password" {
 	type = string
 }
 
 resource "openstack_compute_instance_v2" "good_example" {
   name            = "basic"
   image_id        = "ad091b52-742f-469e-8f3c-fd81cadf0743"
   flavor_id       = "3"
   admin_pass      = var.password
   security_groups = ["default"]
   user_data       = "#cloud-config\nhostname: instance_1.example.com\nfqdn: instance_1.example.com"
 
   network {
     name = "my_network"
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

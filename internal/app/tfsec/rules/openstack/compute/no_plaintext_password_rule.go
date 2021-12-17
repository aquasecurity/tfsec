package compute

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/openstack/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
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
 }`},
		GoodExample: []string{`
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
 }`},
		Links: []string{
			"https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/compute_instance_v2#admin_pass",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"openstack_compute_instance_v2"},
		Base:           compute.CheckNoPlaintextPassword,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("admin_pass") {
				return
			}

			if adminPassAttr := resourceBlock.GetAttribute("admin_pass"); adminPassAttr.IsString() && !adminPassAttr.IsEmpty() {
				results.Add("Resource specifies a plain text password", adminPassAttr)
			}
			return results
		},
	})
}

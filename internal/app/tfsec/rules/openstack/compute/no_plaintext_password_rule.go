package compute

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "compute",
		ShortCode: "no-plaintext-password",
		Documentation: rule.RuleDocumentation{
			Summary:     "No plaintext password for compute instance",
			Explanation: `Assigning a password to the compute instance using plaintext could lead to compromise; it would be preferable to use key-pairs as a login mechanism`,
			Impact:      "Including a plaintext password could lead to compromised instance",
			Resolution:  "Do not use plaintext passwords in terraform files",
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
		},
		Provider:        provider.OpenStackProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"openstack_compute_instance_v2"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("admin_pass") {
				return
			}

			if adminPassAttr := resourceBlock.GetAttribute("admin_pass"); adminPassAttr.IsString() && !adminPassAttr.IsEmpty() {
				set.AddResult().
					WithDescription("Resource '%s' specifies a plain text password", resourceBlock.FullName()).
					WithAttribute(adminPassAttr)
			}
		},
	})
}

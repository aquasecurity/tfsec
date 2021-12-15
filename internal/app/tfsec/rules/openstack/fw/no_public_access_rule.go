package fw

// generator-locked
import (
	"fmt"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/cidr"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "openstack_fw_rule_v1" "rule_1" {
 	name             = "my_rule"
 	description      = "let anyone in"
 	action           = "allow"
 	protocol         = "tcp"
 	destination_port = "22"
 	enabled          = "true"
 }
 			`},
		GoodExample: []string{`
 resource "openstack_fw_rule_v1" "rule_1" {
 	name                   = "my_rule"
 	description            = "don't let just anyone in"
 	action                 = "allow"
 	protocol               = "tcp"
 	destination_ip_address = "10.10.10.1"
 	source_ip_address      = "10.10.10.2"
 	destination_port       = "22"
 	enabled                = "true"
 }
 			`},
		Links: []string{
			"https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/fw_rule_v1",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"openstack_fw_rule_v1"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.GetAttribute("enabled").IsFalse() {
				return
			}

			if resourceBlock.GetAttribute("action").Equals("deny") {
				return
			}

			if destinationIP := resourceBlock.GetAttribute("destination_ip_address"); destinationIP.IsNil() || destinationIP.Equals("") {
				results.Add(
					fmt.Sprintf("Resource defines a firewall rule with no restriction on destination IP", resourceBlock),
				).

			} else if cidr.IsAttributeOpen(destinationIP) {
				results.Add("Resource defines a firewall rule with a public destination CIDR", resourceBlock)
			}

			if sourceIP := resourceBlock.GetAttribute("source_ip_address"); sourceIP.IsNil() || sourceIP.Equals("") {
				results.Add("Resource defines a firewall rule with no restriction on source IP", resourceBlock)
			} else if cidr.IsAttributeOpen(sourceIP) {
				results.Add("Resource defines a firewall rule with a public source CIDR", resourceBlock)
			}
			return results
		},
	})
}

package compute

import (
	"github.com/aquasecurity/defsec/rules/openstack/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
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
		Base:           compute.CheckNoPublicAccess,
	})
}

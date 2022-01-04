package compute

import (
	"github.com/aquasecurity/defsec/rules/cloudstack/compute"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "cloudstack_instance" "web" {
   name             = "server-1"
   service_offering = "small"
   network_id       = "6eb22f91-7454-4107-89f4-36afcdf33021"
   template         = "CentOS 6.5"
   zone             = "zone-1"
   user_data        = <<EOF
 export DATABASE_PASSWORD=\"SomeSortOfPassword\"
 EOF
 }
 `, `
 resource "cloudstack_instance" "web" {
   name             = "server-1"
   service_offering = "small"
   network_id       = "6eb22f91-7454-4107-89f4-36afcdf33021"
   template         = "CentOS 6.5"
   zone             = "zone-1"
   user_data        = "ZXhwb3J0IERBVEFCQVNFX1BBU1NXT1JEPSJTb21lU29ydE9mUGFzc3dvcmQi"
 }
 `},
		GoodExample: []string{`
 resource "cloudstack_instance" "web" {
   name             = "server-1"
   service_offering = "small"
   network_id       = "6eb22f91-7454-4107-89f4-36afcdf33021"
   template         = "CentOS 6.5"
   zone             = "zone-1"
   user_data        = <<EOF
 export GREETING="Hello there"
 EOF
 }
 `, `
 resource "cloudstack_instance" "web" {
   name             = "server-1"
   service_offering = "small"
   network_id       = "6eb22f91-7454-4107-89f4-36afcdf33021"
   template         = "CentOS 6.5"
   zone             = "zone-1"
   user_data        = "ZXhwb3J0IEVESVRPUj12aW1hY3M="
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/cloudstack/latest/docs/resources/instance#",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"cloudstack_instance",
		},
		Base: compute.CheckNoSensitiveInfo,
	})
}

package compute

import (
	"github.com/aquasecurity/defsec/rules/google/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GCP003",
		BadExample: []string{`
 resource "google_compute_firewall" "bad_example" {
    allow {
        protocol = "tcp"
    }
 	source_ranges = ["0.0.0.0/0"]
 }`},
		GoodExample: []string{`
 resource "google_compute_firewall" "good_example" {
    allow {
        protocol = "tcp"
    }
 	source_ranges = ["1.2.3.4/32"]
 }`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#source_ranges",

			"https://www.terraform.io/docs/providers/google/r/compute_firewall.html",
		},
		Base: compute.CheckNoPublicIngress,
	})
}

package compute

import (
	"github.com/aquasecurity/defsec/rules/google/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GCP004",
		BadExample: []string{`
resource "google_compute_firewall" "bad_example" {
  direction = "EGRESS"
  allow {
    protocol = "tcp"
  }
  destination_ranges = ["0.0.0.0/0"]
}`},
		GoodExample: []string{`
resource "google_compute_firewall" "good_example" {
  direction = "EGRESS"
  allow {
    protocol = "tcp"
  }
  destination_ranges = ["10.0.0.1/24"]
}`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall",
		},
		Base: compute.CheckNoPublicEgress,
	})
}

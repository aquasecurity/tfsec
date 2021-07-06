package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_GoogleOpenInboundFirewallRule(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check google_compute_firewall ingress on 0.0.0.0/0",
			source: `
resource "google_compute_firewall" "my-firewall" {
	source_ranges = ["0.0.0.0/0"]
}`,
			mustIncludeResultCode: rules.GoogleOpenInboundFirewallRule,
		},
		{
			name: "check google_compute_firewall ingress on /32",
			source: `
resource "google_compute_firewall" "my-firewall" {
	source_ranges = ["1.2.3.4/32"]
}`,
			mustExcludeResultCode: rules.GoogleOpenInboundFirewallRule,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

func Test_GoogleOpenOutboundFirewallRule(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check google_compute_firewall egress on 0.0.0.0/0",
			source: `
resource "google_compute_firewall" "my-firewall" {
	destination_ranges = ["0.0.0.0/0"]
}`,
			mustIncludeResultCode: rules.GoogleOpenOutboundFirewallRule,
		},
		{
			name: "check google_compute_firewall egress on /32",
			source: `
resource "google_compute_firewall" "my-firewall" {
	destination_ranges = ["1.2.3.4/32"]
}`,
			mustExcludeResultCode: rules.GoogleOpenOutboundFirewallRule,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/google"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_GoogleOpenInboundFirewallRule(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check google_compute_firewall ingress on 0.0.0.0/0",
			source: `
resource "google_compute_firewall" "my-firewall" {
	source_ranges = ["0.0.0.0/0"]
}`,
			mustIncludeResultCode: google.GoogleOpenInboundFirewallRule,
		},
		{
			name: "check google_compute_firewall ingress on /32",
			source: `
resource "google_compute_firewall" "my-firewall" {
	source_ranges = ["1.2.3.4/32"]
}`,
			mustExcludeResultCode: google.GoogleOpenInboundFirewallRule,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

func Test_GoogleOpenOutboundFirewallRule(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check google_compute_firewall egress on 0.0.0.0/0",
			source: `
resource "google_compute_firewall" "my-firewall" {
	destination_ranges = ["0.0.0.0/0"]
}`,
			mustIncludeResultCode: google.GoogleOpenOutboundFirewallRule,
		},
		{
			name: "check google_compute_firewall egress on /32",
			source: `
resource "google_compute_firewall" "my-firewall" {
	destination_ranges = ["1.2.3.4/32"]
}`,
			mustExcludeResultCode: google.GoogleOpenOutboundFirewallRule,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

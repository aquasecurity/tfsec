package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_GkeEnforcePSPTest(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check google_container_cluster with pod_security_policy_config.enabled set to false",
			source: `
resource "google_container_cluster" "gke" {
	pod_security_policy_config {
    enabled = "false"
  }
}`,
			mustIncludeResultCode: checks.GkeEnforcePSP,
		},
		{
			name: "check google_container_cluster with pod_security_policy_config block not set",
			source: `
resource "google_container_cluster" "gke" {

}`,
			mustIncludeResultCode: checks.GkeEnforcePSP,
		},
		{
			name: "check google_container_cluster with pod_security_policy_config.enabled set to true",
			source: `
resource "google_container_cluster" "gke" {
	pod_security_policy_config {
    enabled = "true"
  }
}`,
			mustExcludeResultCode: checks.GkeEnforcePSP,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

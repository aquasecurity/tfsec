package gke

import (
	"github.com/aquasecurity/defsec/rules/google/gke"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GCP009",
		BadExample: []string{`
 resource "google_container_cluster" "bad_example" {
 	pod_security_policy_config {
         enabled = "false"
 	}
 }`},
		GoodExample: []string{`
 resource "google_container_cluster" "good_example" {
 	pod_security_policy_config {
         enabled = "true"
 	}
 }`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#pod_security_policy_config",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		Base:           gke.CheckEnforcePodSecurityPolicy,
	})
}

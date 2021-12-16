package gke

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/google/gke"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#admission_controllers",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		Base:           gke.CheckEnforcePodSecurityPolicy,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("pod_security_policy_config") {
				results.Add("Resource defines a cluster with no Pod Security Policy config defined. It is recommended to define a PSP for your pods and enable PSP enforcement.", resourceBlock)
				return
			}

			enforcePSP := resourceBlock.GetNestedAttribute("pod_security_policy_config.enabled")
			if enforcePSP.IsNotNil() && enforcePSP.IsFalse() {
				results.Add("Resource defines a cluster with Pod Security Policy enforcement disabled. It is recommended to define a PSP for your pods and enable PSP enforcement.", enforcePSP)
			}

			return results
		},
	})
}

package gke

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GCP010",
		BadExample: []string{`
 resource "google_container_cluster" "bad_example" {
 	enable_shielded_nodes = "false"
 }`},
		GoodExample: []string{`
 resource "google_container_cluster" "good_example" {
 	enable_shielded_nodes = "true"
 }`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_shielded_nodes",
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#shielded_nodes",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("enable_shielded_nodes") {
				results.Add("Resource defines a cluster with shielded nodes disabled. Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.", resourceBlock)
				return
			}

			enableShieldedNodesAttr := resourceBlock.GetAttribute("enable_shielded_nodes")
			if enableShieldedNodesAttr.IsFalse() {
				results.Add("Resource defines a cluster with shielded nodes disabled. Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.", enableShieldedNodesAttr)
			}

			return results
		},
	})
}

package gke

import (
	"strings"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/google/gke"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GCP012",
		BadExample: []string{`
 resource "google_container_cluster" "bad_example" {
 	node_config {
 	}
 }
 `},
		GoodExample: []string{`
 resource "google_container_cluster" "good_example" {
 	node_config {
 		service_account = "cool-service-account@example.com"
 	}
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#service_account",
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_sa",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster", "google_container_node_pool"},
		Base:           gke.CheckUseServiceAccount,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if strings.HasPrefix(resourceBlock.Label(), "google_container_cluster") {
				attr := resourceBlock.GetAttribute("remove_default_node_pool")
				if attr.IsNotNil() && attr.IsTrue() {
					return
				}
			}

			if resourceBlock.MissingChild("node_config") {
				results.Add("Resource does not define the node config and does not override the default service account. It is recommended to use a minimally privileged service account to run your GKE cluster.", resourceBlock)
				return
			}

			nodeConfigBlock := resourceBlock.GetBlock("node_config")
			serviceAccount := nodeConfigBlock.GetAttribute("service_account")

			if serviceAccount.IsNil() || serviceAccount.IsEmpty() {
				results.Add("Resource does not override the default service account. It is recommended to use a minimally privileged service account to run your GKE cluster.", resourceBlock)
			}

			return results
		},
	})
}

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
		LegacyID: "GCP005",
		BadExample: []string{`
 resource "google_container_cluster" "bad_example" {
 	enable_legacy_abac = "true"
 }
 `},
		GoodExample: []string{`
 resource "google_container_cluster" "good_example" {
 	# ...
 	# enable_legacy_abac not set
 	# ...
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_legacy_abac",
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#leave_abac_disabled_default_for_110",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			enableLegacyABAC := resourceBlock.GetAttribute("enable_legacy_abac")
			if enableLegacyABAC.IsNotNil() && enableLegacyABAC.IsTrue() {
				results.Add("Resource defines a cluster with ABAC enabled. Disable and rely on RBAC instead. ", enableLegacyABAC)
			}

			return results
		},
	})
}

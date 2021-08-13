package gke

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "GCP005",
		Service:   "gke",
		ShortCode: "use-rbac-permissions",
		Documentation: rule.RuleDocumentation{
			Summary:    "Legacy ABAC permissions are enabled.",
			Impact:     "ABAC permissions are less secure than RBAC permissions",
			Resolution: "Switch to using RBAC permissions",
			Explanation: `
You should disable Attribute-Based Access Control (ABAC), and instead use Role-Based Access Control (RBAC) in GKE.

RBAC has significant security advantages and is now stable in Kubernetes, so it’s time to disable ABAC.
`,
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
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_container_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			enableLegacyABAC := resourceBlock.GetAttribute("enable_legacy_abac")
			if enableLegacyABAC.IsNotNil() && enableLegacyABAC.IsTrue() {
				set.AddResult().
					WithDescription("Resource '%s' defines a cluster with ABAC enabled. Disable and rely on RBAC instead. ", resourceBlock.FullName())
			}

		},
	})
}

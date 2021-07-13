package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const GkeAbacEnabled = "GCP005"
const GkeAbacEnabledDescription = "Legacy ABAC permissions are enabled."
const GkeAbacEnabledImpact = "ABAC permissions are less secure than RBAC permissions"
const GkeAbacEnabledResolution = "Switch to using RBAC permissions"
const GkeAbacEnabledExplanation = `
You should disable Attribute-Based Access Control (ABAC), and instead use Role-Based Access Control (RBAC) in GKE.

RBAC has significant security advantages and is now stable in Kubernetes, so it’s time to disable ABAC.
`
const GkeAbacEnabledBadExample = `
resource "google_container_cluster" "bad_example" {
	enable_legacy_abac = "true"
}
`
const GkeAbacEnabledGoodExample = `
resource "google_container_cluster" "good_example" {
	# ...
	# enable_legacy_abac not set
	# ...
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: GkeAbacEnabled,
		Documentation: rule.RuleDocumentation{
			Summary:     GkeAbacEnabledDescription,
			Impact:      GkeAbacEnabledImpact,
			Resolution:  GkeAbacEnabledResolution,
			Explanation: GkeAbacEnabledExplanation,
			BadExample:  GkeAbacEnabledBadExample,
			GoodExample: GkeAbacEnabledGoodExample,
			Links: []string{
				"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#leave_abac_disabled_default_for_110",
				"https://www.terraform.io/docs/providers/google/r/container_cluster.html#enable_legacy_abac",
			},
		},
		Provider:        provider.GCPProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_container_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			enableLegacyABAC := resourceBlock.GetAttribute("enable_legacy_abac")
			if enableLegacyABAC != nil && enableLegacyABAC.Value().Type() == cty.String && enableLegacyABAC.Value().AsString() == "true" {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a cluster with ABAC enabled. Disable and rely on RBAC instead. ", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			}

		},
	})
}

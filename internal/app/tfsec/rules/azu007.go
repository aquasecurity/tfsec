package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"
)

const AZUAKSClusterRBACenabled = "AZU007"
const AZUAKSClusterRBACenabledDescription = "Ensure RBAC is enabled on AKS clusters"
const AZUAKSClusterRBACenabledImpact = "No role based access control is in place for the AKS cluster"
const AZUAKSClusterRBACenabledResolution = "Enable RBAC"
const AZUAKSClusterRBACenabledExplanation = `
Using Kubernetes role-based access control (RBAC), you can grant users, groups, and service accounts access to only the resources they need.
`
const AZUAKSClusterRBACenabledBadExample = `
resource "azurerm_kubernetes_cluster" "bad_example" {
	role_based_access_control {
		enabled = false
	}
}
`
const AZUAKSClusterRBACenabledGoodExample = `
resource "azurerm_kubernetes_cluster" "good_example" {
	role_based_access_control {
		enabled = true
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AZUAKSClusterRBACenabled,
		Documentation: rule.RuleDocumentation{
			Summary:     AZUAKSClusterRBACenabledDescription,
			Impact:      AZUAKSClusterRBACenabledImpact,
			Resolution:  AZUAKSClusterRBACenabledResolution,
			Explanation: AZUAKSClusterRBACenabledExplanation,
			BadExample:  AZUAKSClusterRBACenabledBadExample,
			GoodExample: AZUAKSClusterRBACenabledGoodExample,
			Links: []string{
				"https://www.terraform.io/docs/providers/azurerm/r/kubernetes_cluster.html#role_based_access_control",
				"https://docs.microsoft.com/en-us/azure/aks/concepts-identity",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_kubernetes_cluster", "role_based_access_control"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			rbacBlock := resourceBlock.GetBlock("role_based_access_control")
			if rbacBlock == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines without RBAC", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			enabledAttr := rbacBlock.GetAttribute("enabled")
			if enabledAttr != nil && enabledAttr.Type() == cty.Bool && enabledAttr.Value().False() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf(
							"Resource '%s' RBAC disabled.",
							resourceBlock.FullName(),
						)).
						WithRange(enabledAttr.Range()).
						WithAttributeAnnotation(enabledAttr),
				)
			}

		},
	})
}

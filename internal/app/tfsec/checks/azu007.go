package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"
)

const AZUAKSClusterRBACenabled scanner.RuleCode = "AZU007"
const AZUAKSClusterRBACenabledDescription scanner.RuleSummary = "Ensure RBAC is enabled on AKS clusters"
const AZUAKSClusterRBACenabledExplanation = `
Using Kubernetes role-based access control (RBAC), you can grant users, groups, and service accounts access to only the resources they need.
`
const AZUAKSClusterRBACenabledBadExample = `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	role_based_access_control {
		enabled = false
	}
}
`
const AZUAKSClusterRBACenabledGoodExample = `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	role_based_access_control {
		enabled = true
	}
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUAKSClusterRBACenabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUAKSClusterRBACenabledDescription,
			Explanation: AZUAKSClusterRBACenabledExplanation,
			BadExample:  AZUAKSClusterRBACenabledBadExample,
			GoodExample: AZUAKSClusterRBACenabledGoodExample,
			Links: []string{
				"https://www.terraform.io/docs/providers/azurerm/r/kubernetes_cluster.html#role_based_access_control",
				"https://docs.microsoft.com/en-us/azure/aks/concepts-identity",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_kubernetes_cluster", "role_based_access_control"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			rbacBlock := block.GetBlock("role_based_access_control")
			if rbacBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines without RBAC", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			enabledAttr := rbacBlock.GetAttribute("enabled")
			if enabledAttr.Type() == cty.Bool && enabledAttr.Value().False() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf(
							"Resource '%s' RBAC disabled.",
							block.FullName(),
						),
						enabledAttr.Range(),
						enabledAttr,
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}

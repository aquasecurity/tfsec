package google

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// GkeEnforcePSP See https://github.com/tfsec/tfsec#included-checks for check info
const GkeEnforcePSP scanner.RuleID = "GCP009"
const GkeEnforcePSPDescription scanner.RuleSummary = "Pod security policy enforcement not defined."
const GkeEnforcePSPExplanation = `

`
const GkeEnforcePSPBadExample = `

`
const GkeEnforcePSPGoodExample = `

`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GkeEnforcePSP,
		Documentation: scanner.CheckDocumentation{
			Summary:     GkeEnforcePSPDescription,
			Explanation: GkeEnforcePSPExplanation,
			BadExample:  GkeEnforcePSPBadExample,
			GoodExample: GkeEnforcePSPGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			pspBlock := block.GetBlock("pod_security_policy_config")
			if pspBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a cluster with no Pod Security Policy config defined. It is recommended to define a PSP for your pods and enable PSP enforcement. https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#admission_controllers", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			enforcePSP := pspBlock.GetAttribute("enabled")
			if enforcePSP.Type() == cty.Bool && enforcePSP.Value().False() || enforcePSP.Type() == cty.String && enforcePSP.Value().AsString() != "true" {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a cluster with Pod Security Policy enforcement disabled. It is recommended to define a PSP for your pods and enable PSP enforcement. https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#admission_controllers", block.Name()),
						enforcePSP.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}

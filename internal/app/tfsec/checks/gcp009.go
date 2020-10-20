package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// GkeEnforcePSP See https://github.com/tfsec/tfsec#included-checks for check info
const GkeEnforcePSP scanner.RuleCode = "GCP009"
const GkeEnforcePSPDescription scanner.RuleSummary = "Pod security policy enforcement not defined."
const GkeEnforcePSPExplanation = `
By default, Pods in Kubernetes can operate with capabilities beyond what they require. You should constrain the Pod's capabilities to only those required for that workload.

Kubernetes offers controls for restricting your Pods to execute with only explicitly granted capabilities. 

Pod Security Policy allows you to set smart defaults for your Pods, and enforce controls you want to enable across your fleet. 

The policies you define should be specific to the needs of your application
`
const GkeEnforcePSPBadExample = `
resource "google_container_cluster" "gke" {
	pod_security_policy_config {
        enabled = "false"
	}
}`
const GkeEnforcePSPGoodExample = `
resource "google_container_cluster" "gke" {
	pod_security_policy_config {
        enabled = "true"
	}
}`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: GkeEnforcePSP,
		Documentation: scanner.CheckDocumentation{
			Summary:     GkeEnforcePSPDescription,
			Explanation: GkeEnforcePSPExplanation,
			BadExample:  GkeEnforcePSPBadExample,
			GoodExample: GkeEnforcePSPGoodExample,
			Links: []string{
				"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#admission_controllers",
				"https://www.terraform.io/docs/providers/google/r/container_cluster.html#pod_security_policy_config",
			},
		},
		Provider:       scanner.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			pspBlock := block.GetBlock("pod_security_policy_config")
			if pspBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a cluster with no Pod Security Policy config defined. It is recommended to define a PSP for your pods and enable PSP enforcement.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			enforcePSP := pspBlock.GetAttribute("enabled")
			if enforcePSP.Type() == cty.Bool && enforcePSP.Value().False() || enforcePSP.Type() == cty.String && enforcePSP.Value().AsString() != "true" {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a cluster with Pod Security Policy enforcement disabled. It is recommended to define a PSP for your pods and enable PSP enforcement.", block.FullName()),
						enforcePSP.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}

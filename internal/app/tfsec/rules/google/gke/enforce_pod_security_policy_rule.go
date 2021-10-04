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
		LegacyID:  "GCP009",
		Service:   "gke",
		ShortCode: "enforce-pod-security-policy",
		Documentation: rule.RuleDocumentation{
			Summary:    "Pod security policy enforcement not defined.",
			Impact:     "Pods could be operating with more permissions than required to be effective",
			Resolution: "Use security policies for pods to restrict permissions to those needed to be effective",
			Explanation: `
By default, Pods in Kubernetes can operate with capabilities beyond what they require. You should constrain the Pod's capabilities to only those required for that workload.

Kubernetes offers controls for restricting your Pods to execute with only explicitly granted capabilities. 

Pod Security Policy allows you to set smart defaults for your Pods, and enforce controls you want to enable across your fleet. 

The policies you define should be specific to the needs of your application
`,
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
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_container_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("pod_security_policy_config") {
				set.AddResult().
					WithDescription("Resource '%s' defines a cluster with no Pod Security Policy config defined. It is recommended to define a PSP for your pods and enable PSP enforcement.", resourceBlock.FullName())
				return
			}

			enforcePSP := resourceBlock.GetNestedAttribute("pod_security_policy_config.enabled")
			if enforcePSP.IsNotNil() && enforcePSP.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' defines a cluster with Pod Security Policy enforcement disabled. It is recommended to define a PSP for your pods and enable PSP enforcement.", resourceBlock.FullName())
			}

		},
	})
}

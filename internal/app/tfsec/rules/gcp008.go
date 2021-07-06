package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// GkeLegacyAuthEnabled See https://github.com/tfsec/tfsec#included-checks for check info
const GkeLegacyAuthEnabled = "GCP008"
const GkeLegacyAuthEnabledDescription = "Legacy client authentication methods utilized."
const GkeLegacyAuthEnabledImpact = "Username and password authentication methods are less secure"
const GkeLegacyAuthEnabledResolution = "Use service account or OAuth for authentication"
const GkeLegacyAuthEnabledExplanation = `
It is recommended to use Serivce Accounts and OAuth as authentication methods for accessing the master in the container cluster. 

Basic authentication should be disabled by explicitly unsetting the <code>username</code> and <code>password</code> on the <code>master_auth</code> block.
`
const GkeLegacyAuthEnabledBadExample = `
resource "google_container_cluster" "bad_example" {
}

resource "google_container_cluster" "gke" {
	master_auth {
	    username = ""
	    password = ""
		client_certificate_config {
			issue_client_certificate = true
	    }
	}
}
`
const GkeLegacyAuthEnabledGoodExample = `
resource "google_container_cluster" "good_example" {
	master_auth {
	    username = ""
	    password = ""
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: GkeLegacyAuthEnabled,
		Documentation: rule.RuleDocumentation{
			Summary:     GkeLegacyAuthEnabledDescription,
			Impact:      GkeLegacyAuthEnabledImpact,
			Resolution:  GkeLegacyAuthEnabledResolution,
			Explanation: GkeLegacyAuthEnabledExplanation,
			BadExample:  GkeLegacyAuthEnabledBadExample,
			GoodExample: GkeLegacyAuthEnabledGoodExample,
			Links: []string{
				"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_authn_methods",
				"https://www.terraform.io/docs/providers/google/r/container_cluster.html#master_auth",
			},
		},
		Provider:        provider.GCPProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_container_cluster"},
		DefaultSeverity: severity.Error,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			masterAuthBlock := resourceBlock.GetBlock("master_auth")
			if masterAuthBlock == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not disable basic auth with static passwords for client authentication. Disable this with a master_auth block container empty strings for user and password.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()).
						WithSeverity(severity.Error),
				)
				return
			}

			staticAuthPass := masterAuthBlock.GetAttribute("password")
			if staticAuthPass != nil && !staticAuthPass.IsEmpty() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a cluster using basic auth with static passwords for client authentication. It is recommended to use OAuth or service accounts instead.", resourceBlock.FullName())).
						WithRange(masterAuthBlock.Range()).
						WithSeverity(severity.Error),
				)
			}

			if masterAuthBlock.MissingChild("client_certificate_config") {
				return
			}

			issueClientCert := masterAuthBlock.GetBlock("client_certificate_config").GetAttribute("issue_client_certificate")
			if issueClientCert != nil && issueClientCert.IsTrue() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a cluster using basic auth with client certificates for authentication. This cert has no permissions if RBAC is enabled and ABAC is disabled. It is recommended to use OAuth or service accounts instead.", resourceBlock.FullName())).
						WithRange(issueClientCert.Range()).
						WithSeverity(severity.Error),
				)
			}

		},
	})
}

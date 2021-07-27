package gke

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "GCP008",
		Service:   "gke",
		ShortCode: "no-legacy-authentication",
		Documentation: rule.RuleDocumentation{
			Summary:    "Legacy client authentication methods utilized.",
			Impact:     "Username and password authentication methods are less secure",
			Resolution: "Use service account or OAuth for authentication",
			Explanation: `
It is recommended to use Service Accounts and OAuth as authentication methods for accessing the master in the container cluster. 

Basic authentication should be disabled by explicitly unsetting the <code>username</code> and <code>password</code> on the <code>master_auth</code> block.
`,
			BadExample: []string{`
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
`},
			GoodExample: []string{`
resource "google_container_cluster" "good_example" {
	master_auth {
	    username = ""
	    password = ""
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#master_auth",
				"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_authn_methods",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_container_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			masterAuthBlock := resourceBlock.GetBlock("master_auth")
			if masterAuthBlock == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not disable basic auth with static passwords for client authentication. Disable this with a master_auth block container empty strings for user and password.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			staticAuthPass := masterAuthBlock.GetAttribute("password")
			if staticAuthPass != nil && !staticAuthPass.IsEmpty() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines a cluster using basic auth with static passwords for client authentication. It is recommended to use OAuth or service accounts instead.", resourceBlock.FullName())).
						WithRange(masterAuthBlock.Range()),
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
						WithRange(issueClientCert.Range()),
				)
			}

		},
	})
}

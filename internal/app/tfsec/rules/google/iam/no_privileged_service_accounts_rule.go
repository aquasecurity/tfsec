package iam

// generator-locked
import (
	"strings"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "iam",
		ShortCode: "no-privileged-service-accounts",
		Documentation: rule.RuleDocumentation{
			Summary:     "Service accounts should not have roles assigned with excessive privileges",
			Explanation: `Service accounts should have a minimal set of permissions assigned in order to do their job. They should never have excessive access as if compromised, an attacker can escalate privileges and take over the entire account.`,
			Impact:      "Cloud account takeover if a resource using a service account is compromised",
			Resolution:  "Limit service account access to minimal required set",
			BadExample: []string{`
resource "google_service_account" "test" {
  account_id   = "account123"
  display_name = "account123"
}

resource "google_project_iam_member" "project" {
	project = "your-project-id"
	role    = "roles/owner"
	member  = "serviceAccount:${google_service_account.test.email}"
}
			`},
			GoodExample: []string{`
resource "google_service_account" "test" {
	account_id   = "account123"
	display_name = "account123"
}

resource "google_project_iam_member" "project" {
	project = "your-project-id"
	role    = "roles/logging.logWriter"
	member  = "serviceAccount:${google_service_account.test.email}"
}
			`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam",
				"https://cloud.google.com/iam/docs/understanding-roles",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_project_iam_member"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {

			// is this a sensitive role?
			roleAttr := resourceBlock.GetAttribute("role")
			if !roleAttr.IsString() {
				return
			}
			if !isRolePrivileged(roleAttr.Value().AsString()) {
				return
			}

			// is it linked to a service account?
			memberAttr := resourceBlock.GetAttribute("member")
			if memberAttr.IsNil() {
				return
			}
			if memberAttr.IsString() {
				if memberAttr.StartsWith("serviceAccount:") {
					set.AddResult().
						WithDescription("Resource '%s' provides privileged access to a service account", resourceBlock).
						WithAttribute(roleAttr)
				}
			}

			// the service account may be populated via a templated reference that we don't have, so we need to check references
			if serviceAccountBlock, err := module.GetReferencedBlock(memberAttr); err != nil {
				return
			} else if serviceAccountBlock.IsNotNil() && serviceAccountBlock.TypeLabel() == "google_service_account" {
				set.AddResult().
					WithDescription("Resource '%s' provides privileged access to service account at %s", resourceBlock, serviceAccountBlock.FullName()).
					WithAttribute(roleAttr)
			}
		},
	})
}

func isRolePrivileged(role string) bool {
	switch {
	case role == "roles/owner":
		return true
	case role == "roles/editor":
		return true
	case strings.HasSuffix(strings.ToLower(role), "admin"):
		return true
	}
	return false
}

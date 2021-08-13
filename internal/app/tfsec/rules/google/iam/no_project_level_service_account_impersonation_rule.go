package iam

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
		Service:   "iam",
		ShortCode: "no-project-level-service-account-impersonation",
		Documentation: rule.RuleDocumentation{
			Summary:     "Users should not be granted service account access at the project level",
			Explanation: `Users with service account access at project level can impersonate any service account. Instead, they should be given access to particular service accounts as required.`,
			Impact:      "Privilege escalation, impersonation of any/all services",
			Resolution:  "Provide access at the service-level instead of project-level, if required",
			BadExample: []string{
				`
resource "google_project_iam_binding" "project-123" {
	project = "project-123"
	role    = "roles/iam.serviceAccountUser"
}
`,
				`
resource "google_project_iam_binding" "project-123" {
	project = "project-123"
	role    = "roles/iam.serviceAccountTokenCreator"
}
`,
			},
			GoodExample: []string{`
resource "google_project_iam_binding" "project-123" {
	project = "project-123"
	role    = "roles/nothingInParticular"
}
			`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam",
				"https://cloud.google.com/iam/docs/impersonating-service-accounts",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_project_iam_binding", "google_project_iam_member"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			roleAttr := resourceBlock.GetAttribute("role")
			if !roleAttr.IsString() {
				return
			}
			if roleAttr.IsAny("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
				set.AddResult().
					WithAttribute(roleAttr).
					WithDescription("Resource '%s' grants service account access to a user at project level.", resourceBlock.FullName())
			}

		},
	})
}

package iam

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
		ShortCode: "no-folder-level-service-account-impersonation",
		Documentation: rule.RuleDocumentation{
			Summary:     "Users should not be granted service account access at the folder level",
			Explanation: `Users with service account access at folder level can impersonate any service account. Instead, they should be given access to particular service accounts as required.`,
			Impact:      "Privilege escalation, impersonation of any/all services",
			Resolution:  "Provide access at the service-level instead of folder-level, if required",
			BadExample: []string{
				`
resource "google_folder_iam_binding" "folder-123" {
	folder = "folder-123"
	role    = "roles/iam.serviceAccountUser"
}
`,
				`
resource "google_folder_iam_binding" "folder-123" {
	folder = "folder-123"
	role    = "roles/iam.serviceAccountTokenCreator"
}
`,
			},
			GoodExample: []string{`
resource "google_folder_iam_binding" "folder-123" {
	folder = "folder-123"
	role    = "roles/nothingInParticular"
}
			`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_folder_iam",
				"https://cloud.google.com/iam/docs/impersonating-service-accounts",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_folder_iam_binding", "google_folder_iam_member"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			roleAttr := resourceBlock.GetAttribute("role")
			if !roleAttr.IsString() {
				return
			}
			if roleAttr.IsAny("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
				set.AddResult().
					WithAttribute(roleAttr).
					WithDescription("Resource '%s' grants service account access to a user at folder level.", resourceBlock.FullName())
			}

		},
	})
}

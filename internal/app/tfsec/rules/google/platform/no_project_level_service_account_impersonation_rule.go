package platform

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/google/platform"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_project_iam_binding", "google_project_iam_member"},
		Base:           platform.CheckNoProjectLevelServiceAccountImpersonation,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			roleAttr := resourceBlock.GetAttribute("role")
			if !roleAttr.IsString() {
				return
			}
			if roleAttr.IsAny("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
				results.Add("Resource grants service account access to a user at project level.", roleAttr)
			}

			return results
		},
	})
}

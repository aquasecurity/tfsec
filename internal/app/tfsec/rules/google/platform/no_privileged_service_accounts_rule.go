package platform

import (
	"strings"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/google/platform"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_project_iam_member"},
		Base:           platform.CheckNoPrivilegedServiceAccounts,
		CheckTerraform: func(resourceBlock block.Block, module block.Module) (results rules.Results) {

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
					results.Add("Resource provides privileged access to a service account", resourceBlock)
				}
			}

			// the service account may be populated via a templated reference that we don't have, so we need to check references
			if serviceAccountBlock, err := module.GetReferencedBlock(memberAttr, resourceBlock); err != nil {
				return
			} else if serviceAccountBlock.IsNotNil() && serviceAccountBlock.TypeLabel() == "google_service_account" {
				results.Add("Resource provides privileged access to service account", serviceAccountBlock)
			}
			return results
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

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
 resource "google_project_iam_member" "project-123" {
 	project = "project-123"
 	role    = "roles/whatever"
 	member  = "123-compute@developer.gserviceaccount.com"
 }
 `,
			`
 resource "google_project_iam_member" "project-123" {
 	project = "project-123"
 	role    = "roles/whatever"
 	member  = "123@appspot.gserviceaccount.com"
 }
 `, `
 data "google_compute_default_service_account" "default" {
 }
 
 resource "google_project_iam_member" "project-123" {
 	project = "project-123"
 	role    = "roles/whatever"
 	member  = data.google_compute_default_service_account.default.id
 }
 `,
		},
		GoodExample: []string{`
 resource "google_service_account" "test" {
 	account_id   = "account123"
 	display_name = "account123"
 }
 			  
 resource "google_project_iam_member" "project-123" {
 	project = "project-123"
 	role    = "roles/whatever"
 	member  = "serviceAccount:${google_service_account.test.email}"
 }
 `,
		},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam",
			"",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_project_iam_binding", "google_project_iam_member"},
		Base:           platform.CheckNoProjectLevelDefaultServiceAccountAssignment,
		CheckTerraform: func(resourceBlock block.Block, module block.Module) (results rules.Results) {

			if memberAttr := resourceBlock.GetAttribute("member"); memberAttr.IsNotNil() {
				if memberAttr.IsString() {
					if isMemberDefaultServiceAccount(memberAttr.Value().AsString()) {
						results.Add("Resource assigns a role to a default service account.", memberAttr)
					}
				} else {
					computeServiceAccounts := module.GetDatasByType("google_compute_default_service_account")
					serviceAccounts := append(computeServiceAccounts, module.GetResourcesByType("google_app_engine_default_service_account")...)
					for _, serviceAccount := range serviceAccounts {
						if memberAttr.References(serviceAccount.Reference()) {
							results.Add("Resource assigns a role to a default service account.", memberAttr)
						}
					}
				}
			}

			if membersAttr := resourceBlock.GetAttribute("members"); membersAttr.IsNotNil() {
				for _, member := range membersAttr.ValueAsStrings() {
					if isMemberDefaultServiceAccount(member) {
						results.Add("Resource assigns a role to a default service account.", membersAttr)
					}
				}
				computeServiceAccounts := module.GetDatasByType("google_compute_default_service_account")
				serviceAccounts := append(computeServiceAccounts, module.GetResourcesByType("google_app_engine_default_service_account")...)
				for _, serviceAccount := range serviceAccounts {
					if membersAttr.References(serviceAccount.Reference()) {
						results.Add("Resource assigns a role to a default service account.", membersAttr)
					}
				}
			}

			return results
		},
	})
}

func isMemberDefaultServiceAccount(member string) bool {
	return strings.HasSuffix(member, "-compute@developer.gserviceaccount.com") || strings.HasSuffix(member, "@appspot.gserviceaccount.com")
}

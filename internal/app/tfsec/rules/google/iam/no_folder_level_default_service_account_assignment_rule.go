package iam

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/google/iam"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "google_folder_iam_member" "folder-123" {
 	folder = "folder-123"
 	role    = "roles/whatever"
 	member  = "123-compute@developer.gserviceaccount.com"
 }
 `,
			`
 resource "google_folder_iam_member" "folder-123" {
 	folder = "folder-123"
 	role    = "roles/whatever"
 	member  = "123@appspot.gserviceaccount.com"
 }
 `, `
 data "google_compute_default_service_account" "default" {
 }
 
 resource "google_folder_iam_member" "folder-123" {
 	folder = "folder-123"
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
 			  
 resource "google_folder_iam_member" "folder-123" {
 	folder = "folder-123"
 	role    = "roles/whatever"
 	member  = "serviceAccount:${google_service_account.test.email}"
 }
 `,
		},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_folder_iam",
			"",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_folder_iam_binding", "google_folder_iam_member"},
		Base:           iam.CheckNoFolderLevelDefaultServiceAccountAssignment,
		CheckTerraform: func(resourceBlock block.Block, module block.Module) (results rules.Results) {

			if memberAttr := resourceBlock.GetAttribute("member"); memberAttr.IsNotNil() {
				if memberAttr.IsString() {
					if isMemberDefaultServiceAccount(memberAttr.Value().AsString()) {
						results.Add("Resource assigns a role to a default service account.", memberAttr)
					}
				} else {
					computeServiceAccounts := module.GetDatasByType("google_compute_default_service_account")
					computeServiceAccounts = append(computeServiceAccounts, module.GetResourcesByType("google_app_engine_default_service_account")...)
					for _, serviceAccount := range computeServiceAccounts {
						if memberAttr.References(serviceAccount.Reference()) {
							results.Add("Resource assigns a role to a default service account.", serviceAccount)
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
				computeServiceAccounts = append(computeServiceAccounts, module.GetResourcesByType("google_app_engine_default_service_account")...)
				for _, serviceAccount := range computeServiceAccounts {
					if membersAttr.References(serviceAccount.Reference()) {
						results.Add("Resource assigns a role to a default service account.", membersAttr)
					}
				}
			}

			return results
		},
	})
}

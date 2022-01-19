package iam

import (
	"github.com/aquasecurity/defsec/rules/google/iam"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_folder_iam_binding", "google_folder_iam_member"},
		Base:           iam.CheckNoFolderLevelServiceAccountImpersonation,
	})
}

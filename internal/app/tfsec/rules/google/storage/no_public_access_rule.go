package storage

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/google/storage"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "google_storage_bucket_iam_binding" "binding" {
 	bucket = google_storage_bucket.default.name
 	role = "roles/storage.admin"
 	members = [
 		"allAuthenticatedUsers",
 	]
 }
 			`},
		GoodExample: []string{`
 resource "google_storage_bucket_iam_binding" "binding" {
 	bucket = google_storage_bucket.default.name
 	role = "roles/storage.admin"
 	members = [
 		"user:jane@example.com",
 	]
 }
 			`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket_iam#member/members",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_storage_bucket_iam_binding", "google_storage_bucket_iam_member"},
		Base:           storage.CheckNoPublicAccess,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if memberAttr := resourceBlock.GetAttribute("member"); memberAttr.IsString() {
				if googleIAMMemberIsExternal(memberAttr.Value().AsString()) {
					results.Add("Resource allows public access via member attribute.", memberAttr)
				}
			}

			if membersAttr := resourceBlock.GetAttribute("members"); membersAttr.IsNotNil() {
				for _, member := range membersAttr.ValueAsStrings() {
					if googleIAMMemberIsExternal(member) {
						results.Add("Resource allows public access via members attribute.", membersAttr)
					}
				}
			}

			return results
		},
	})
}

func googleIAMMemberIsExternal(member string) bool {
	return member == "allUsers" || member == "allAuthenticatedUsers"
}

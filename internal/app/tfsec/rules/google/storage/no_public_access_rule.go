package storage

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
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
			"https://jbrojbrojbro.medium.com/you-make-the-rules-with-authentication-controls-for-cloud-storage-53c32543747b",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_storage_bucket_iam_binding", "google_storage_bucket_iam_member"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if memberAttr := resourceBlock.GetAttribute("member"); memberAttr.IsString() {
				if googleIAMMemberIsExternal(memberAttr.Value().AsString()) {
					results.Add("Resource allows public access via member attribute.", ?)
				}
			}

			if membersAttr := resourceBlock.GetAttribute("members"); membersAttr.IsNotNil() {
				for _, member := range membersAttr.ValueAsStrings() {
					if googleIAMMemberIsExternal(member) {
						results.Add("Resource allows public access via members attribute.", ?)
					}
				}
			}

			return results
		},
	})
}

func googleIAMMemberIsExternal(member
string) bool{
return member == "allUsers" || member == "allAuthenticatedUsers"
}

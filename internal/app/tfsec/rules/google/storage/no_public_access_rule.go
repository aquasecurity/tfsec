package storage
 
 // generator-locked
 import (
 	"github.com/aquasecurity/defsec/result"
 	"github.com/aquasecurity/defsec/severity"
 
 	"github.com/aquasecurity/defsec/provider"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
 
 	"github.com/aquasecurity/tfsec/pkg/rule"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
 )
 
 func init() {
 	scanner.RegisterCheckRule(rule.Rule{
 		Service:   "storage",
 		ShortCode: "no-public-access",
 		Documentation: rule.RuleDocumentation{
 			Summary:     "Ensure that Cloud Storage bucket is not anonymously or publicly accessible.",
 			Explanation: `Using 'allUsers' or 'allAuthenticatedUsers' as members in an IAM member/binding causes data to be exposed outside of the organisation.`,
 			Impact:      "Public exposure of sensitive data.",
 			Resolution:  "Restrict public access to the bucket.",
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
 		},
 		Provider:        provider.GoogleProvider,
 		RequiredTypes:   []string{"resource"},
 		RequiredLabels:  []string{"google_storage_bucket_iam_binding", "google_storage_bucket_iam_member"},
 		DefaultSeverity: severity.High,
 		CheckTerraform: func(set result.Set, resourceBlock block.Block, _ block.Module) {
 
 			if memberAttr := resourceBlock.GetAttribute("member"); memberAttr.IsString() {
 				if googleIAMMemberIsExternal(memberAttr.Value().AsString()) {
 					set.AddResult().WithDescription("Resource '%s' allows public access via member attribute.", resourceBlock.FullName()).
 						WithAttribute("")
 				}
 			}
 
 			if membersAttr := resourceBlock.GetAttribute("members"); membersAttr.IsNotNil() {
 				for _, member := range membersAttr.ValueAsStrings() {
 					if googleIAMMemberIsExternal(member) {
 						set.AddResult().WithDescription("Resource '%s' allows public access via members attribute.", resourceBlock.FullName()).
 							WithAttribute("")
 					}
 				}
 			}
 
 		},
 	})
 }
 
 func googleIAMMemberIsExternal(member string) bool {
 	return member == "allUsers" || member == "allAuthenticatedUsers"
 }

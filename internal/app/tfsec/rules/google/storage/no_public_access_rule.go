package storage

import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

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
			BadExample: `
resource "google_storage_bucket_iam_binding" "binding" {
	bucket = google_storage_bucket.default.name
	role = "roles/storage.admin"
	members = [
		"allAuthenticatedUsers",
	]
}
			`,
			GoodExample: `
resource "google_storage_bucket_iam_binding" "binding" {
	bucket = google_storage_bucket.default.name
	role = "roles/storage.admin"
	members = [
		"user:jane@example.com",
	]
}
			`,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket_iam#member/members",
				"https://jbrojbrojbro.medium.com/you-make-the-rules-with-authentication-controls-for-cloud-storage-53c32543747b",
			},
		},
		Provider:        provider.GoogleProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"google_storage_bucket_iam_binding", "google_storage_bucket_iam_member"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if memberAttr := resourceBlock.GetAttribute("member"); memberAttr != nil && memberAttr.IsString() {
				if googleIAMMemberIsExternal(memberAttr.Value().AsString()) {
					set.Add(result.New(resourceBlock).
						WithDescription("Resource '%s' allows public access via member attribute.").
						WithAttribute(memberAttr),
					)
				}
			}

			if membersAttr := resourceBlock.GetAttribute("members"); membersAttr != nil {
				for _, member := range membersAttr.ValueAsStrings() {
					if googleIAMMemberIsExternal(member) {
						set.Add(result.New(resourceBlock).
							WithDescription("Resource '%s' allows public access via members attribute.").
							WithAttribute(membersAttr),
						)
					}
				}
			}

		},
	})
}

func googleIAMMemberIsExternal(member string) bool {
	return member == "allUsers" || member == "allAuthenticatedUsers"
}

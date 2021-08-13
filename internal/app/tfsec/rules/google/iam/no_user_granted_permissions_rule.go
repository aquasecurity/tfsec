package iam

// generator-locked
import (
	"strings"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "GCP011",
		Service:   "iam",
		ShortCode: "no-user-granted-permissions",
		Documentation: rule.RuleDocumentation{
			Summary:    "IAM granted directly to user.",
			Impact:     "Users shouldn't have permissions granted to them directly",
			Resolution: "Roles should be granted permissions and assigned to users",
			Explanation: `
Permissions should not be directly granted to users, you identify roles that contain the appropriate permissions, and then grant those roles to the user. 

Granting permissions to users quickly become unwieldy and complex to make large scale changes to remove access to a particular resource.

Permissions should be granted on roles, groups, services accounts instead.
`,
			BadExample: []string{`
resource "google_project_iam_binding" "bad_example" {
	members = [
		"user:test@example.com",
		]
}

resource "google_project_iam_member" "bad_example" {
	member = "user:test@example.com"
}
`},
			GoodExample: []string{`
resource "google_project_iam_binding" "good_example" {
	members = [
		"group:test@example.com",
		]
}

resource "google_storage_bucket_iam_member" "good_example" {
	member = "serviceAccount:test@example.com"
}`},
			Links: []string{
				"https://www.terraform.io/docs/providers/google/d/iam_policy.html#members",
				"https://cloud.google.com/iam/docs/overview#permissions",
				"https://cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy",
			},
		},
		Provider:      provider.GoogleProvider,
		RequiredTypes: []string{"resource", "data"},
		RequiredLabels: []string{
			"google_cloud_run_service_iam_binding",
			"google_cloud_run_service_iam_member",
			"google_compute_instance_iam_binding",
			"google_compute_instance_iam_member",
			"google_compute_subnetwork_iam_binding",
			"google_compute_subnetwork_iam_member",
			"google_data_catalog_entry_group_iam_binding",
			"google_data_catalog_entry_group_iam_member",
			"google_folder_iam_member",
			"google_folder_iam_binding",
			"google_project_iam_member",
			"google_project_iam_binding",
			"google_pubsub_subscription_iam_binding",
			"google_pubsub_subscription_iam_member",
			"google_pubsub_topic_iam_binding",
			"google_pubsub_topic_iam_member",
			"google_sourcerepo_repository_iam_binding",
			"google_sourcerepo_repository_iam_member",
			"google_spanner_database_iam_binding",
			"google_spanner_database_iam_member",
			"google_spanner_instance_iam_binding",
			"google_spanner_instance_iam_member",
			"google_storage_bucket_iam_binding",
			"google_storage_bucket_iam_member",
			"google_iam_policy",
		},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			var members []cty.Value
			var attribute block.Attribute

			if attribute = resourceBlock.GetAttribute("member"); attribute.IsNotNil() {
				members = append(members, attribute.Value())
			} else if attribute = resourceBlock.GetAttribute("members"); attribute.IsNotNil() {
				members = attribute.Value().AsValueSlice()
			} else if resourceBlock.HasChild("binding") {
				if attribute = resourceBlock.GetBlock("binding").GetAttribute("members"); attribute.IsNotNil() {
					members = attribute.Value().AsValueSlice()
				}
			}
			for _, identities := range members {
				if identities.IsKnown() && identities.Type() == cty.String && strings.HasPrefix(identities.AsString(), "user:") {
					set.AddResult().
						WithDescription("'%s' grants IAM to a user object. It is recommended to manage user permissions with groups.", resourceBlock.FullName())
				}
			}
		},
	})
}

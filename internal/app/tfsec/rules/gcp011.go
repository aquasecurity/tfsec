package rules

import (
	"fmt"
	"strings"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// GoogleUserIAMGrant See https://github.com/tfsec/tfsec#included-checks for check info
const GoogleUserIAMGrant = "GCP011"
const GoogleUserIAMGrantDescription = "IAM granted directly to user."
const GoogleUserIAMGrantImpact = "Users shouldn't have permissions granted to them directly"
const GoogleUserIAMGrantResolution = "Roles should be granted permissions and assigned to users"
const GoogleUserIAMGrantExplanation = `
Permissions should not be directly granted to users, you identify roles that contain the appropriate permissions, and then grant those roles to the user. 

Granting permissions to users quickly become unwieldy and complex to make large scale changes to remove access to a particular resource.

Permissions should be granted on roles, groups, services accounts instead.
`
const GoogleUserIAMGrantBadExample = `
resource "google_project_iam_binding" "bad_example" {
	members = [
		"user:test@example.com",
		]
}

resource "google_project_iam_member" "bad_example" {
	member = "user:test@example.com"
}
`
const GoogleUserIAMGrantGoodExample = `
resource "google_project_iam_binding" "good_example" {
	members = [
		"group:test@example.com",
		]
}

resource "google_storage_bucket_iam_member" "good_example" {
	member = "serviceAccount:test@example.com"
}`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: GoogleUserIAMGrant,
		Documentation: rule.RuleDocumentation{
			Summary:     GoogleUserIAMGrantDescription,
			Impact:      GoogleUserIAMGrantImpact,
			Resolution:  GoogleUserIAMGrantResolution,
			Explanation: GoogleUserIAMGrantExplanation,
			BadExample:  GoogleUserIAMGrantBadExample,
			GoodExample: GoogleUserIAMGrantGoodExample,
			Links: []string{
				"https://cloud.google.com/iam/docs/overview#permissions",
				"https://cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy",
				"https://www.terraform.io/docs/providers/google/d/iam_policy.html#members",
			},
		},
		Provider:      provider.GCPProvider,
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
		CheckFunc: func(set result.Set, b *block.Block, _ *hclcontext.Context) {

			var members []cty.Value
			var attributes *block.Attribute

			if attributes = b.GetAttribute("member"); attributes != nil {
				members = append(members, attributes.Value())
			} else if attributes = b.GetAttribute("members"); attributes != nil {
				members = attributes.Value().AsValueSlice()
			} else if attributes = b.GetBlock("binding").GetAttribute("members"); attributes != nil {
				members = attributes.Value().AsValueSlice()
			}
			for _, identities := range members {
				if identities.IsKnown() && identities.Type() == cty.String && strings.HasPrefix(identities.AsString(), "user:") {
					set.Add(
						result.New().
							WithDescription(fmt.Sprintf("'%s' grants IAM to a user object. It is recommended to manage user permissions with groups.", b.FullName())).
							WithRange(attributes.Range()).
							WithSeverity(severity.Warning),
					)
				}
			}

		},
	})
}

package platform

import (
	"strings"

	"github.com/aquasecurity/defsec/rules/google/platform"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/zclconf/go-cty/cty"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GCP011",
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
		},
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
		Base: platform.CheckNoUserGrantedPermissions,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

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
					results.Add("'%s' grants IAM to a user object. It is recommended to manage user permissions with groups.", resourceBlock)
				}
			}
			return results
		},
	})
}

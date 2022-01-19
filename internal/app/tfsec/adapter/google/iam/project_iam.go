package iam

import (
	"github.com/aquasecurity/defsec/provider/google/iam"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

// see https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam

func (a *adapter) adaptProjectIAM(modules block.Modules) {
	a.adaptProjectMembers(modules)
	a.adaptProjectBindings(modules)
}

func (a *adapter) adaptMember(iamBlock block.Block) iam.Member {
	var member iam.Member
	roleAttr := iamBlock.GetAttribute("role")
	memberAttr := iamBlock.GetAttribute("member")
	member.Role = roleAttr.AsStringValueOrDefault("", iamBlock)
	member.Member = memberAttr.AsStringValueOrDefault("", iamBlock)
	return member
}

var projectMemberResources = []string{
	"google_project_iam_member",
	"google_cloud_run_service_iam_member",
	"google_compute_instance_iam_member",
	"google_compute_subnetwork_iam_member",
	"google_data_catalog_entry_group_iam_member",
	"google_folder_iam_member",
	"google_project_iam_member",
	"google_pubsub_subscription_iam_member",
	"google_pubsub_topic_iam_member",
	"google_sourcerepo_repository_iam_member",
	"google_spanner_database_iam_member",
	"google_spanner_instance_iam_member",
	"google_storage_bucket_iam_member",
}

func (a *adapter) adaptProjectMembers(modules block.Modules) {
	for _, memberType := range projectMemberResources {
		for _, iamBlock := range modules.GetResourcesByType(memberType) {
			member := a.adaptMember(iamBlock)
			projectAttr := iamBlock.GetAttribute("project")
			if projectAttr.IsString() {
				var foundProject bool
				projectID := projectAttr.Value().AsString()
				for i, project := range a.projects {
					if project.id == projectID {
						project.project.Members = append(project.project.Members, member)
						a.projects[i] = project
						foundProject = true
						break
					}
				}
				if foundProject {
					continue
				}
			}

			if refBlock, err := modules.GetReferencedBlock(projectAttr, iamBlock); err == nil {
				if refBlock.TypeLabel() == "google_project" {
					var foundProject bool
					for i, project := range a.projects {
						if project.blockID == refBlock.ID() {
							project.project.Members = append(project.project.Members, member)
							a.projects[i] = project
							foundProject = true
							break
						}
					}
					if !foundProject {
						continue
					}

				}
			}

			// we didn't find the project - add an unmanaged one
			a.projects = append(a.projects, parentedProject{
				project: iam.Project{
					AutoCreateNetwork: nil,
					Members:           []iam.Member{member},
				},
			})
		}
	}
}

func (a *adapter) adaptBinding(iamBlock block.Block) iam.Binding {
	var binding iam.Binding
	roleAttr := iamBlock.GetAttribute("role")
	membersAttr := iamBlock.GetAttribute("member")
	binding.Role = roleAttr.AsStringValueOrDefault("", iamBlock)
	for _, member := range membersAttr.ValueAsStrings() {
		binding.Members = append(binding.Members, types.String(member, membersAttr.Metadata()))
	}
	return binding
}

var projectBindingResources = []string{
	"google_project_iam_binding",
	"google_cloud_run_service_iam_binding",
	"google_compute_instance_iam_binding",
	"google_compute_subnetwork_iam_binding",
	"google_data_catalog_entry_group_iam_binding",
	"google_folder_iam_binding",
	"google_project_iam_binding",
	"google_pubsub_subscription_iam_binding",
	"google_pubsub_topic_iam_binding",
	"google_sourcerepo_repository_iam_binding",
	"google_spanner_database_iam_binding",
	"google_spanner_instance_iam_binding",
	"google_storage_bucket_iam_binding",
}

func (a *adapter) adaptProjectBindings(modules block.Modules) {
	for _, bindingType := range projectBindingResources {
		for _, iamBlock := range modules.GetResourcesByType(bindingType) {
			binding := a.adaptBinding(iamBlock)
			projectAttr := iamBlock.GetAttribute("project")
			if projectAttr.IsString() {
				var foundProject bool
				projectID := projectAttr.Value().AsString()
				for i, project := range a.projects {
					if project.id == projectID {
						project.project.Bindings = append(project.project.Bindings, binding)
						a.projects[i] = project
						foundProject = true
						break
					}
				}
				if foundProject {
					continue
				}
			}

			if refBlock, err := modules.GetReferencedBlock(projectAttr, iamBlock); err == nil {
				if refBlock.TypeLabel() == "google_project" {
					var foundProject bool
					for i, project := range a.projects {
						if project.blockID == refBlock.ID() {
							project.project.Bindings = append(project.project.Bindings, binding)
							a.projects[i] = project
							foundProject = true
							break
						}
					}
					if !foundProject {
						continue
					}

				}
			}

			// we didn't find the project - add an unmanaged one
			a.projects = append(a.projects, parentedProject{
				project: iam.Project{
					AutoCreateNetwork: nil,
					Bindings:          []iam.Binding{binding},
				},
			})
		}
	}
}

package iam

import (
	"github.com/aquasecurity/defsec/provider/google/iam"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

type parentedProject struct {
	blockID       string
	orgBlockID    string
	folderBlockID string
	id            string
	orgID         string
	folderID      string
	project       iam.Project
}

func (a *adapter) adaptProjects(modules block.Modules) {
	for _, projectBlock := range modules.GetResourcesByType("google_project") {
		var project parentedProject
		idAttr := projectBlock.GetAttribute("project_id")
		if !idAttr.IsString() {
			continue
		}
		project.id = idAttr.Value().AsString()

		project.blockID = projectBlock.ID()

		orgAttr := projectBlock.GetAttribute("org_id")
		if orgAttr.IsString() {
			project.orgID = orgAttr.Value().AsString()
		}
		folderAttr := projectBlock.GetAttribute("folder_id")
		if folderAttr.IsString() {
			project.folderID = folderAttr.Value().AsString()
		}

		autoCreateNetworkAttr := projectBlock.GetAttribute("auto_create_network")
		project.project.AutoCreateNetwork = autoCreateNetworkAttr.AsBoolValueOrDefault(true, projectBlock)

		if orgAttr.IsNotNil() {
			if referencedBlock, err := modules.GetReferencedBlock(orgAttr, projectBlock); err == nil {
				if referencedBlock.TypeLabel() == "google_organization" {
					project.orgBlockID = referencedBlock.ID()
					a.addOrg(project.orgBlockID)
				}
			}
		}
		if folderAttr.IsNotNil() {
			if referencedBlock, err := modules.GetReferencedBlock(folderAttr, projectBlock); err == nil {
				if referencedBlock.TypeLabel() == "google_folder" {
					project.folderBlockID = referencedBlock.ID()
				}
			}
		}
		a.projects = append(a.projects, project)
	}
}

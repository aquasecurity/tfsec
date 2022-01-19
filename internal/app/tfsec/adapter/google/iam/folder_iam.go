package iam

import (
	"github.com/aquasecurity/defsec/provider/google/iam"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

// see https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_folder_iam

func (a *adapter) adaptFolderIAM(modules block.Modules) {
	a.adaptFolderMembers(modules)
	a.adaptFolderBindings(modules)
}

func (a *adapter) adaptFolderMembers(modules block.Modules) {
	for _, iamBlock := range modules.GetResourcesByType("google_folder_iam_member") {
		member := a.adaptMember(iamBlock)
		folderAttr := iamBlock.GetAttribute("folder")
		if refBlock, err := modules.GetReferencedBlock(folderAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == "google_folder" {
				var foundFolder bool
				for i, folder := range a.folders {
					if folder.blockID == refBlock.ID() {
						folder.folder.Members = append(folder.folder.Members, member)
						a.folders[i] = folder
						foundFolder = true
						break
					}
				}
				if !foundFolder {
					continue
				}

			}
		}

		// we didn't find the folder - add an unmanaged one
		a.folders = append(a.folders, parentedFolder{
			folder: iam.Folder{
				Members: []iam.Member{member},
			},
		})
	}
}

func (a *adapter) adaptFolderBindings(modules block.Modules) {
	for _, iamBlock := range modules.GetResourcesByType("google_folder_iam_binding") {
		binding := a.adaptBinding(iamBlock)
		folderAttr := iamBlock.GetAttribute("folder")
		if refBlock, err := modules.GetReferencedBlock(folderAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == "google_folder" {
				var foundFolder bool
				for i, folder := range a.folders {
					if folder.blockID == refBlock.ID() {
						folder.folder.Bindings = append(folder.folder.Bindings, binding)
						a.folders[i] = folder
						foundFolder = true
						break
					}
				}
				if !foundFolder {
					continue
				}

			}
		}

		// we didn't find the folder - add an unmanaged one
		a.folders = append(a.folders, parentedFolder{
			folder: iam.Folder{
				Bindings: []iam.Binding{binding},
			},
		})
	}
}

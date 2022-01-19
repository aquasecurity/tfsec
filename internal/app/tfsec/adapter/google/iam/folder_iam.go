package iam

import (
	"github.com/aquasecurity/defsec/provider/google/iam"
)

// see https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_folder_iam

func (a *adapter) adaptFolderIAM() {
	a.adaptFolderMembers()
	a.adaptFolderBindings()
}

func (a *adapter) adaptFolderMembers() {
	for _, iamBlock := range a.modules.GetResourcesByType("google_folder_iam_member") {
		member := a.adaptMember(iamBlock)
		folderAttr := iamBlock.GetAttribute("folder")
		if refBlock, err := a.modules.GetReferencedBlock(folderAttr, iamBlock); err == nil {
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
				if foundFolder {
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

func (a *adapter) adaptFolderBindings() {
	for _, iamBlock := range a.modules.GetResourcesByType("google_folder_iam_binding") {
		binding := a.adaptBinding(iamBlock)
		folderAttr := iamBlock.GetAttribute("folder")
		if refBlock, err := a.modules.GetReferencedBlock(folderAttr, iamBlock); err == nil {
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
				if foundFolder {
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

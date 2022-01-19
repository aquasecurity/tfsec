package iam

import (
	"github.com/aquasecurity/defsec/provider/google/iam"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

type parentedFolder struct {
	blockID       string
	parentBlockID string
	parentRef     string
	folder        iam.Folder
}

func (a *adapter) adaptFolders(modules block.Modules) {
	for _, folderBlock := range modules.GetResourcesByType("google_folder") {
		var folder parentedFolder
		parentAttr := folderBlock.GetAttribute("parent")
		if parentAttr.IsNil() {
			continue
		}

		folder.blockID = folderBlock.ID()
		if parentAttr.IsString() {
			folder.parentRef = parentAttr.Value().AsString()
		}

		if referencedBlock, err := modules.GetReferencedBlock(parentAttr, folderBlock); err == nil {
			if referencedBlock.TypeLabel() == "google_folder" {
				folder.parentBlockID = referencedBlock.ID()
			}
			if referencedBlock.TypeLabel() == "google_organization" {
				folder.parentBlockID = referencedBlock.ID()
				a.addOrg(folder.parentBlockID)
			}
		}

		a.folders = append(a.folders, folder)
	}
}

package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AZUBlobStorageContainerNoPublicAccess(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check there is an error when the public access is set to blob",
			source: `
resource "azure_storage_container" "blob_storage_container" {
	name                  = "terraform-container-storage"
	container_access_type = "blob"
	
	properties = {
		"publicAccess" = "blob"
	}
}
`,
			mustIncludeResultCode: rules.AZUBlobStorageContainerNoPublicAccess,
		},
		{
			name: "check there is an error when the public access is set to container",
			source: `
resource "azure_storage_container" "blob_storage_container" {
	name                  = "terraform-container-storage"
	container_access_type = "blob"
	
	properties = {
		"publicAccess" = "container"
	}
}
`,
			mustIncludeResultCode: rules.AZUBlobStorageContainerNoPublicAccess,
		},
		{
			name: "check there is no failure when the public access is set to off",
			source: `
resource "azure_storage_container" "blob_storage_container" {
	name                  = "terraform-container-storage"
	container_access_type = "blob"
	
	properties = {
		"publicAccess" = "off"
	}
}
`,
			mustExcludeResultCode: rules.AZUBlobStorageContainerNoPublicAccess,
		},
		{
			name: "check there is no failure when public access level is not set",
			source: `
resource "azure_storage_container" "blob_storage_container" {
	name                  = "terraform-container-storage"
	container_access_type = "blob"
	
	properties = {
		"publicAccess" = "off"
	}
}
`,
			mustExcludeResultCode: rules.AZUBlobStorageContainerNoPublicAccess,
		},
		{
			name: "check there is no failure when no properties are supplied",
			source: `
resource "azure_storage_container" "blob_storage_container" {
	name                  = "terraform-container-storage"
	container_access_type = "blob"

}
`,
			mustExcludeResultCode: rules.AZUBlobStorageContainerNoPublicAccess,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

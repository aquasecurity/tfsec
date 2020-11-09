package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AZUBlobStorageContainerNoPublicAccess(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
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
			mustIncludeResultCode: checks.AZUBlobStorageContainerNoPublicAccess,
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
			mustIncludeResultCode: checks.AZUBlobStorageContainerNoPublicAccess,
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
			mustExcludeResultCode: checks.AZUBlobStorageContainerNoPublicAccess,
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
			mustExcludeResultCode: checks.AZUBlobStorageContainerNoPublicAccess,
		},
		{
			name: "check there is no failure when no properties are supplied",
			source: `
resource "azure_storage_container" "blob_storage_container" {
	name                  = "terraform-container-storage"
	container_access_type = "blob"

}
`,
			mustExcludeResultCode: checks.AZUBlobStorageContainerNoPublicAccess,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

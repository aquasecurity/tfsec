package storage
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AZUBlobStorageContainerNoPublicAccess(t *testing.T) {
// 	expectedCode := "azure-storage-no-public-access"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "check there is an error when the public access is set to blob",
// 			source: `
// resource "azure_storage_container" "blob_storage_container" {
// 	name                  = "terraform-container-storage"
// 	container_access_type = "blob"
// 	
// 	properties = {
// 		"publicAccess" = "blob"
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check there is an error when the public access is set to container",
// 			source: `
// resource "azure_storage_container" "blob_storage_container" {
// 	name                  = "terraform-container-storage"
// 	container_access_type = "blob"
// 	
// 	properties = {
// 		"publicAccess" = "container"
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check there is no failure when the public access is set to off",
// 			source: `
// resource "azure_storage_container" "blob_storage_container" {
// 	name                  = "terraform-container-storage"
// 	container_access_type = "blob"
// 	
// 	properties = {
// 		"publicAccess" = "off"
// 	}
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check there is no failure when public access level is not set",
// 			source: `
// resource "azure_storage_container" "blob_storage_container" {
// 	name                  = "terraform-container-storage"
// 	container_access_type = "blob"
// 	
// 	properties = {
// 		"publicAccess" = "off"
// 	}
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check there is no failure when no properties are supplied",
// 			source: `
// resource "azure_storage_container" "blob_storage_container" {
// 	name                  = "terraform-container-storage"
// 	container_access_type = "blob"
// 
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 	}
// 
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 
// 			results := testutil.ScanHCL(test.source, t)
// 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
// 		})
// 	}
// 
// }

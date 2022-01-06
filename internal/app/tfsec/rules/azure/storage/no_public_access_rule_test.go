package storage

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AZUBlobStorageContainerNoPublicAccess(t *testing.T) {
	expectedCode := "azure-storage-no-public-access"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check there is an error when the container access type is set to blob",
			source: `
 resource "azurerm_storage_account" "example" {
	name                     = "examplestoraccount"
 }
 
 resource "azurerm_storage_container" "blob_storage_container" {
 	name                  = "terraform-container-storage"
 	container_access_type = "blob"
	storage_account_name  = azurerm_storage_account.example.name
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check there is an error when the container access type is set to container",
			source: `
 resource "azurerm_storage_account" "example" {
	name                     = "examplestoraccount"
 }

 resource "azurerm_storage_container" "blob_storage_container" {
 	name                  = "terraform-container-storage"
	storage_account_name  = azurerm_storage_account.example.name
 	container_access_type = "container"
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check there is no failure when the container access type is set to private",
			source: `
 resource "azurerm_storage_account" "example" {
 	name                     = "examplestoraccount"
 }

 resource "azurerm_storage_container" "blob_storage_container" {
 	name                  = "terraform-container-storage"
	storage_account_name  = azurerm_storage_account.example.name
 	container_access_type = "private"
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check there is no failure when container access type is not set",
			source: `
 resource "azurerm_storage_account" "example" {
 	name                     = "examplestoraccount"
 }

 resource "azurerm_storage_container" "blob_storage_container" {
 	name                  = "terraform-container-storage"
	storage_account_name  = azurerm_storage_account.example.name
	container_access_type = ""
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check there is no failure when no container access type is supplied",
			source: `
 resource "azurerm_storage_account" "example" {
	name                     = "examplestoraccount"
 }

 resource "azurerm_storage_container" "blob_storage_container" {
 	name                  = "terraform-container-storage"
	storage_account_name  = azurerm_storage_account.example.name
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

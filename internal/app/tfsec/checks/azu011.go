package checks

import (
	"fmt"
	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUBlobStorageContainerNoPublicAccess scanner.RuleCode = "AZU011"
const AZUBlobStorageContainerNoPublicAccessDescription scanner.RuleSummary = "Storage containers in blob storage mode should not have public access"
const AZUBlobStorageContainerNoPublicAccessExplanation = `
Storage container public access should be off. It can be configured for blobs only, containers and blobs or off entirely. The default is off, with no public access.

Explicitly overriding publicAccess to anything other than off should be avoided.
`
const AZUBlobStorageContainerNoPublicAccessBadExample = `
resource "azure_storage_container" "blob_storage_container" {
	name                  = "terraform-container-storage"
	container_access_type = "blob"
	
	properties = {
		"publicAccess" = "blob"
	}
}
`
const AZUBlobStorageContainerNoPublicAccessGoodExample = `
resource "azure_storage_container" "blob_storage_container" {
	name                  = "terraform-container-storage"
	container_access_type = "blob"
	
	properties = {
		"publicAccess" = "off"
	}
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUBlobStorageContainerNoPublicAccess,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUBlobStorageContainerNoPublicAccessDescription,
			Explanation: AZUBlobStorageContainerNoPublicAccessExplanation,
			BadExample:  AZUBlobStorageContainerNoPublicAccessBadExample,
			GoodExample: AZUBlobStorageContainerNoPublicAccessGoodExample,
			Links: []string{
				"https://www.terraform.io/docs/providers/azure/r/storage_container.html#properties",
				"https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal#set-the-public-access-level-for-a-container",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azure_storage_container"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			// function contents here
			if block.HasChild("properties") {
				properties := block.GetAttribute("properties")
				if properties.Contains("publicAccess") {
					value := properties.MapValue("publicAccess")
					if value == cty.StringVal("blob") || value == cty.StringVal("container") {
						return []scanner.Result{
							check.NewResult(
								fmt.Sprintf("Resource '%s' defines publicAccess as '%s', should be 'off .", block.FullName(), value),
								block.Range(),
								scanner.SeverityError,
							),
						}
					}
				}
			}

			return nil
		},
	})
}

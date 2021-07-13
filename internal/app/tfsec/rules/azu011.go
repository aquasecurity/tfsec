package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AZUBlobStorageContainerNoPublicAccess = "AZU011"
const AZUBlobStorageContainerNoPublicAccessDescription = "Storage containers in blob storage mode should not have public access"
const AZUBlobStorageContainerNoPublicAccessImpact = "Data in the storage container could be exposed publicly"
const AZUBlobStorageContainerNoPublicAccessResolution = "Disable public access to storage containers"
const AZUBlobStorageContainerNoPublicAccessExplanation = `
Storage container public access should be off. It can be configured for blobs only, containers and blobs or off entirely. The default is off, with no public access.

Explicitly overriding publicAccess to anything other than off should be avoided.
`
const AZUBlobStorageContainerNoPublicAccessBadExample = `
resource "azure_storage_container" "bad_example" {
	name                  = "terraform-container-storage"
	container_access_type = "blob"
	
	properties = {
		"publicAccess" = "blob"
	}
}
`
const AZUBlobStorageContainerNoPublicAccessGoodExample = `
resource "azure_storage_container" "good_example" {
	name                  = "terraform-container-storage"
	container_access_type = "blob"
	
	properties = {
		"publicAccess" = "off"
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AZUBlobStorageContainerNoPublicAccess,
		Documentation: rule.RuleDocumentation{
			Summary:     AZUBlobStorageContainerNoPublicAccessDescription,
			Impact:      AZUBlobStorageContainerNoPublicAccessImpact,
			Resolution:  AZUBlobStorageContainerNoPublicAccessResolution,
			Explanation: AZUBlobStorageContainerNoPublicAccessExplanation,
			BadExample:  AZUBlobStorageContainerNoPublicAccessBadExample,
			GoodExample: AZUBlobStorageContainerNoPublicAccessGoodExample,
			Links: []string{
				"https://www.terraform.io/docs/providers/azure/r/storage_container.html#properties",
				"https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal#set-the-public-access-level-for-a-container",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azure_storage_container"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			// function contents here
			if resourceBlock.HasChild("properties") {
				properties := resourceBlock.GetAttribute("properties")
				if properties != nil && properties.Contains("publicAccess") {
					value := properties.MapValue("publicAccess")
					if value == cty.StringVal("blob") || value == cty.StringVal("container") {
						set.Add(
							result.New(resourceBlock).
								WithDescription(fmt.Sprintf("Resource '%s' defines publicAccess as '%s', should be 'off .", resourceBlock.FullName(), value)).
								WithRange(resourceBlock.Range()),
						)
					}
				}
			}

		},
	})
}

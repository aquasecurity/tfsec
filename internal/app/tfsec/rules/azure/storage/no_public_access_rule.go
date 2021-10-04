package storage

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AZU011",
		Service:   "storage",
		ShortCode: "no-public-access",
		Documentation: rule.RuleDocumentation{
			Summary:    "Storage containers in blob storage mode should not have public access",
			Impact:     "Data in the storage container could be exposed publicly",
			Resolution: "Disable public access to storage containers",
			Explanation: `
Storage container public access should be off. It can be configured for blobs only, containers and blobs or off entirely. The default is off, with no public access.

Explicitly overriding publicAccess to anything other than off should be avoided.
`,
			BadExample: []string{`
resource "azure_storage_container" "bad_example" {
	name                  = "terraform-container-storage"
	container_access_type = "blob"
	
	properties = {
		"publicAccess" = "blob"
	}
}
`},
			GoodExample: []string{`
resource "azure_storage_container" "good_example" {
	name                  = "terraform-container-storage"
	container_access_type = "blob"
	
	properties = {
		"publicAccess" = "off"
	}
}
`},
			Links: []string{
				"https://www.terraform.io/docs/providers/azure/r/storage_container.html#properties",
				"https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal#set-the-public-access-level-for-a-container",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azure_storage_container"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("properties") {
				return
			}
			properties := resourceBlock.GetAttribute("properties")
			if properties.Contains("publicAccess") {
				value := properties.MapValue("publicAccess")
				if value == cty.StringVal("blob") || value == cty.StringVal("container") {
					set.AddResult().
						WithDescription("Resource '%s' defines publicAccess as '%s', should be 'off .", resourceBlock.FullName(), value).WithAttribute(properties)
				}
			}
		},
	})
}

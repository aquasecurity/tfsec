package storage

// generator-locked
import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "storage",
		ShortCode: "container-activity-logs-not-public",
		Documentation: rule.RuleDocumentation{
			Summary:    "Ensure public access level for Blob Containers is set to private",
			Impact:     "Data in the storage container could be exposed publicly",
			Resolution: "Disable public access to storage containers",
			Explanation: `
			Anonymous, public read access to a container and its blobs can be enabled in Azure Blob storage. It grants read-only access to these resources without sharing the account key or requiring a shared access signature.

			We recommend you do not provide anonymous access to blob containers until, and unless, it is strongly desired. A shared access signature token should be used for providing controlled and timed access to blob containers.`,
			BadExample: []string{`
resource "azurerm_storage_container" "bad_example" {
	name                  = "terraform-container-storage"
	container_access_type = "public"
}
`},
			GoodExample: []string{`
resource "azurerm_storage_container" "good_example" {
	name                  = "terraform-container-storage"
	container_access_type = "private"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_container#container_access_type",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_storage_container"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.HasChild("container_access_type") {
				httpsOnlyAttr := resourceBlock.GetAttribute("container_access_type")
				if httpsOnlyAttr.NotEqual("private") {
					set.AddResult().
						WithDescription("Resource '%s' does not have private access level to blob containers.", resourceBlock.FullName())
				}
			} else {
				return
			}

		},
	})
}

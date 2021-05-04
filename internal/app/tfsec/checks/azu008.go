package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUAKSAPIServerAuthorizedIPRanges scanner.RuleCode = "AZU008"
const AZUAKSAPIServerAuthorizedIPRangesDescription scanner.RuleSummary = "Ensure AKS has an API Server Authorized IP Ranges enabled"
const AZUAKSAPIServerAuthorizedIPRangesImpact = "Any IP can interact with the API server"
const AZUAKSAPIServerAuthorizedIPRangesResolution = "Limit the access to the API server to a limited IP range"
const AZUAKSAPIServerAuthorizedIPRangesExplanation = `
The API server is the central way to interact with and manage a cluster. To improve cluster security and minimize attacks, the API server should only be accessible from a limited set of IP address ranges.
`
const AZUAKSAPIServerAuthorizedIPRangesBadExample = `
resource "azurerm_kubernetes_cluster" "bad_example" {

}
`
const AZUAKSAPIServerAuthorizedIPRangesGoodExample = `
resource "azurerm_kubernetes_cluster" "good_example" {
    api_server_authorized_ip_ranges = [
		"1.2.3.4/32"
	]
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUAKSAPIServerAuthorizedIPRanges,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUAKSAPIServerAuthorizedIPRangesDescription,
			Impact:      AZUAKSAPIServerAuthorizedIPRangesImpact,
			Resolution:  AZUAKSAPIServerAuthorizedIPRangesResolution,
			Explanation: AZUAKSAPIServerAuthorizedIPRangesExplanation,
			BadExample:  AZUAKSAPIServerAuthorizedIPRangesBadExample,
			GoodExample: AZUAKSAPIServerAuthorizedIPRangesGoodExample,
			Links: []string{
				"https://docs.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges",
				"https://www.terraform.io/docs/providers/azurerm/r/kubernetes_cluster.html#api_server_authorized_ip_ranges",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_kubernetes_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if (block.MissingChild("api_server_authorized_ip_ranges") ||
				block.GetAttribute("api_server_authorized_ip_ranges").Value().LengthInt() < 1) &&
				(block.MissingChild("private_cluster_enabled") ||
					block.GetAttribute("private_cluster_enabled").IsFalse()) {
				{
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' defined without limited set of IP address ranges to the API server.", block.FullName()),
							block.Range(),
							scanner.SeverityError,
						),
					}
				}
			}
			return nil
		},
	})
}

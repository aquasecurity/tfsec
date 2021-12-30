package monitor

import (
	"github.com/aquasecurity/defsec/rules/azure/monitor"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 
 resource "azurerm_monitor_log_profile" "bad_example" {
   name = "bad_example"
 
   categories = []
 
   locations = [
     "westus",
     "global",
   ]
 
   retention_policy {
     enabled = true
     days    = 7
   }
 }
 `},
		GoodExample: []string{`
 resource "azurerm_monitor_log_profile" "bad_example" {
   name = "bad_example"
 
   categories = []
 
   locations = [
 	"eastus",
 	"eastus2",
 	"southcentralus",
 	"westus2",
 	"westus3",
 	"australiaeast",
 	"southeastasia",
 	"northeurope",
 	"swedencentral",
 	"uksouth",
 	"westeurope",
 	"centralus",
 	"northcentralus",
 	"westus",
 	"southafricanorth",
 	"centralindia",
 	"eastasia",
 	"japaneast",
 	"jioindiawest",
 	"koreacentral",
 	"canadacentral",
 	"francecentral",
 	"germanywestcentral",
 	"norwayeast",
 	"switzerlandnorth",
 	"uaenorth",
 	"brazilsouth",
 	"centralusstage",
 	"eastusstage",
 	"eastus2stage",
 	"northcentralusstage",
 	"southcentralusstage",
 	"westusstage",
 	"westus2stage",
 	"asia",
 	"asiapacific",
 	"australia",
 	"brazil",
 	"canada",
 	"europe",
 	"global",
 	"india",
 	"japan",
 	"uk",
 	"unitedstates",
 	"eastasiastage",
 	"southeastasiastage",
 	"centraluseuap",
 	"eastus2euap",
 	"westcentralus",
 	"southafricawest",
 	"australiacentral",
 	"australiacentral2",
 	"australiasoutheast",
 	"japanwest",
 	"jioindiacentral",
 	"koreasouth",
 	"southindia",
 	"westindia",
 	"canadaeast",
 	"francesouth",
 	"germanynorth",
 	"norwaywest",
 	"swedensouth",
 	"switzerlandwest",
 	"ukwest",
 	"uaecentral",
 	"brazilsoutheast",
   ]
 
   retention_policy {
     enabled = true
     days    = 7
   }
 }
 
 			`},

		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile#locations",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_monitor_log_profile"},
		Base:           monitor.CheckCaptureAllRegions,
	})
}

var locations = []string{
	"eastus",
	"eastus2",
	"southcentralus",
	"westus2",
	"westus3",
	"australiaeast",
	"southeastasia",
	"northeurope",
	"swedencentral",
	"uksouth",
	"westeurope",
	"centralus",
	"northcentralus",
	"westus",
	"southafricanorth",
	"centralindia",
	"eastasia",
	"japaneast",
	"jioindiawest",
	"koreacentral",
	"canadacentral",
	"francecentral",
	"germanywestcentral",
	"norwayeast",
	"switzerlandnorth",
	"uaenorth",
	"brazilsouth",
	"centralusstage",
	"eastusstage",
	"eastus2stage",
	"northcentralusstage",
	"southcentralusstage",
	"westusstage",
	"westus2stage",
	"asia",
	"asiapacific",
	"australia",
	"brazil",
	"canada",
	"europe",
	"global",
	"india",
	"japan",
	"uk",
	"unitedstates",
	"eastasiastage",
	"southeastasiastage",
	"centraluseuap",
	"eastus2euap",
	"westcentralus",
	"southafricawest",
	"australiacentral",
	"australiacentral2",
	"australiasoutheast",
	"japanwest",
	"jioindiacentral",
	"koreasouth",
	"southindia",
	"westindia",
	"canadaeast",
	"francesouth",
	"germanynorth",
	"norwaywest",
	"swedensouth",
	"switzerlandwest",
	"ukwest",
	"uaecentral",
	"brazilsoutheast",
}

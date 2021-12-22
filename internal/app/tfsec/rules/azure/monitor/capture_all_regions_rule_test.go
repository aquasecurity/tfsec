package monitor

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AzureCaptureAllRegions(t *testing.T) {
	expectedCode := "azure-monitor-capture-all-regions"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "profile with empty locations fails check",
			source: `
 resource "azurerm_monitor_log_profile" "bad_example" {
   name = "bad_example"
 
   categories = []
 
   locations = [  ]
 
   retention_policy {
     enabled = true
     days    = 7
   }
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "profile with missing location fails check",
			source: `
 resource "azurerm_monitor_log_profile" "bad_example" {
   name = "bad_example"
 
   categories = []
 
   locations = [
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
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "profile with all required locations passes check",
			source: `
 resource "azurerm_monitor_log_profile" "good_example" {
   name = "good_example"
 
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

package database

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "database",
		ShortCode: "mysql-threat-detection-enabled",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure databases are not publicly accessible",
			Explanation: `My SQL server does not enable Threat Detection policy`,
			Impact:      "Threat detection helps prevent compromise by alerting on threat detections",
			Resolution:  "Enable threat detection on Mysql database",
			BadExample: []string{`
resource "azurerm_mysql_server" "bad_example" {
  name                = "bad_example"

  public_network_access_enabled    = true
  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_2"

  threat_detection_policy {
    enabled = false
  }
}
`},
			GoodExample: []string{`
resource "azurerm_mysql_server" "good_example" {
  name                = "good_example"

  public_network_access_enabled    = false
  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_2"

  threat_detection_policy {
    enabled = true
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/mysql_server#threat_detection_policy",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_mysql_server"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("threat_detection_policy") {
				set.AddResult().
					WithDescription("Mysql server '%s' does not have threat detection policy configured. By default it is disabled.", resourceBlock.FullName())
				return
			}

			tdpBlock := resourceBlock.GetBlock("threat_detection_policy")
			if tdpBlock.MissingChild("enabled") {
				set.AddResult().
					WithDescription("Mysql server '%s' threat detection policy block is empty. By default Threat detection policy is disabled.", resourceBlock.FullName()).
					WithBlock(tdpBlock)
			}

			if tdpEnabledAttr := tdpBlock.GetAttribute("enabled"); tdpEnabledAttr.IsFalse() {
				set.AddResult().
					WithDescription("Mysql Server '%s' has disabled threat detection policy", resourceBlock.FullName()).
					WithAttribute(tdpEnabledAttr)
			}
		},
	})
}

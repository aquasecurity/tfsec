package compute

// ATTENTION!
// This rule was autogenerated!
// Before making changes, consider updating the generator.

import (
	"encoding/base64"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
	"github.com/owenrumney/squealer/pkg/squealer"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Provider:  provider.CloudStackProvider,
		Service:   "compute",
		ShortCode: "no-sensitive-info",
		Documentation: rule.RuleDocumentation{
			Summary:     "No sensitive data stored in user_data",
			Explanation: `When creating instances, user data can be used during the initial configuration. User data must not contain sensitive information`,
			Impact:      "Sensitive credentials in the user data can be leaked",
			Resolution:  "Don't use sensitive data in the user data section",
			BadExample: []string{`
resource "cloudstack_instance" "web" {
  name             = "server-1"
  service_offering = "small"
  network_id       = "6eb22f91-7454-4107-89f4-36afcdf33021"
  template         = "CentOS 6.5"
  zone             = "zone-1"
  user_data        = <<EOF
export DATABASE_PASSWORD=\"SomeSortOfPassword\"
EOF
}
`, `
resource "cloudstack_instance" "web" {
  name             = "server-1"
  service_offering = "small"
  network_id       = "6eb22f91-7454-4107-89f4-36afcdf33021"
  template         = "CentOS 6.5"
  zone             = "zone-1"
  user_data        = "ZXhwb3J0IERBVEFCQVNFX1BBU1NXT1JEPSJTb21lU29ydE9mUGFzc3dvcmQi"
}
`},
			GoodExample: []string{`
resource "cloudstack_instance" "web" {
  name             = "server-1"
  service_offering = "small"
  network_id       = "6eb22f91-7454-4107-89f4-36afcdf33021"
  template         = "CentOS 6.5"
  zone             = "zone-1"
  user_data        = <<EOF
export GREETING="Hello there"
EOF
}
`, `
resource "cloudstack_instance" "web" {
  name             = "server-1"
  service_offering = "small"
  network_id       = "6eb22f91-7454-4107-89f4-36afcdf33021"
  template         = "CentOS 6.5"
  zone             = "zone-1"
  user_data        = "ZXhwb3J0IEVESVRPUj12aW1hY3M="
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/cloudstack/latest/docs/resources/instance#",
			},
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"cloudstack_instance",
		},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			customDataAttr := resourceBlock.GetAttribute("user_data")

			if customDataAttr.IsNotNil() && customDataAttr.IsString() {
				encoded, err := base64.StdEncoding.DecodeString(customDataAttr.Value().AsString())
				if err != nil {
					debug.Log("could not decode the base64 string in the terraform, trying with the string verbatim")
					encoded = []byte(customDataAttr.Value().AsString())
				}
				if checkStringForSensitive(string(encoded)) {
					set.AddResult().
						WithDescription("Resource '%s' has user_data_base64 with sensitive data.", resourceBlock.FullName()).
						WithAttribute(customDataAttr)
				}
			}

		},
	})
}

func checkStringForSensitive(stringToCheck string) bool {
	scanResult := squealer.NewStringScanner().Scan(stringToCheck)
	return scanResult.TransgressionFound
}

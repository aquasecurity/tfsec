package secrets

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/general/secrets"
	"github.com/aquasecurity/tfsec/internal/pkg/scanner"
	"github.com/aquasecurity/tfsec/internal/pkg/security"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/trivy-config-parsers/terraform"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		RequiredTypes: []string{"resource", "provider", "module", "locals", "variable"},
		Base:          secrets.CheckNotExposed,
		CheckTerraform: func(resourceBlock *terraform.Block, _ *terraform.Module) (results rules.Results) {
			attributes := resourceBlock.GetAttributes()
			for _, attribute := range attributes {
				if attribute.IsString() {
					if scanResult := security.StringScanner.Scan(attribute.Value().AsString()); scanResult.TransgressionFound {
						results.Add(
							"A potentially sensitive string was discovered within an attribute value.",
							attribute,
						)
					}
				}
			}
			return results
		},
	})
}

package secrets

import (
	"github.com/aquasecurity/defsec/rules/general/secrets"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/pkg/scanner"
	"github.com/aquasecurity/tfsec/internal/pkg/security"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/trivy-config-parsers/terraform"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		RequiredTypes: []string{"locals"},
		Base:          secrets.CheckNotExposed,
		CheckTerraform: func(resourceBlock *terraform.Block, _ *terraform.Module) (results rules.Results) {
			for _, attribute := range resourceBlock.GetAttributes() {
				if security.IsSensitiveAttribute(attribute.Name()) {
					if attribute.Type() == cty.String && attribute.IsResolvable() {
						results.Add(
							"Local has a name which indicates it may be sensitive, and contains a value which is defined inside the project.",
							attribute,
						)
					}
				}
			}
			return results
		},
	})
}

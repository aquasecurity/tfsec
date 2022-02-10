package secrets

import (
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/general/secrets"
	"github.com/aquasecurity/trivy-config-parsers/terraform"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/pkg/security"

	"github.com/aquasecurity/tfsec/internal/pkg/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		RequiredTypes: []string{"variable"},
		Base:          secrets.CheckNotExposed,
		CheckTerraform: func(resourceBlock *terraform.Block, _ *terraform.Module) (results rules.Results) {

			if len(resourceBlock.Labels()) == 0 || !security.IsSensitiveAttribute(resourceBlock.TypeLabel()) {
				return
			}

			for _, attribute := range resourceBlock.GetAttributes() {
				if attribute.Name() == "default" {
					if attribute.Type() == cty.String && attribute.IsResolvable() {
						results.Add(
							"Variable includes a potentially sensitive default value.",
							attribute,
						)
					}
				}
			}
			return results
		},
	})
}

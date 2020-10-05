package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/security"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/zclconf/go-cty/cty"
)

// GenericSensitiveLocals See https://github.com/tfsec/tfsec#included-checks for check info
const GenericSensitiveLocals scanner.RuleID = "GEN002"
const GenericSensitiveLocalsDescription scanner.RuleDescription = "Potentially sensitive data stored in local value."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:          GenericSensitiveLocals,
		Description:   GenericSensitiveLocalsDescription,
		Provider:      scanner.GeneralProvider,
		RequiredTypes: []string{"locals"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			var results []scanner.Result

			for _, attribute := range block.GetAttributes() {
				if security.IsSensitiveAttribute(attribute.Name()) {
					if attribute.Type() == cty.String && attribute.Value().AsString() != "" {
						results = append(results, check.NewResultWithValueAnnotation(
							fmt.Sprintf("Local '%s' includes a potentially sensitive value which is defined within the project.", block.Name()),
							attribute.Range(),
							attribute,
							scanner.SeverityWarning,
						))
					}
				}
			}

			return results
		},
	})
}

package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/security"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/zclconf/go-cty/cty"
)

// GenericSensitiveVariables See https://github.com/tfsec/tfsec#included-checks for check info
const GenericSensitiveVariables scanner.RuleID = "GEN001"
const GenericSensitiveVariablesDescription scanner.RuleDescription = "Potentially sensitive data stored in \"default\" value of variable."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:          GenericSensitiveVariables,
		Description:   GenericSensitiveVariablesDescription,
		Provider:      scanner.GeneralProvider,
		RequiredTypes: []string{"variable"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if len(block.Labels()) == 0 {
				return nil
			}

			if !security.IsSensitiveAttribute(block.Labels()[0]) {
				return nil
			}

			var results []scanner.Result

			for _, attribute := range block.GetAttributes() {
				if attribute.Name() == "default" {
					val := attribute.Value()
					if val.Type() != cty.String {
						continue
					}
					if val.AsString() != "" {
						results = append(results, check.NewResultWithValueAnnotation(
							fmt.Sprintf("Variable '%s' includes a potentially sensitive default value.", block.Name()),
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

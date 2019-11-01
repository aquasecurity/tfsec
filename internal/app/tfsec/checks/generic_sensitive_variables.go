package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
	"github.com/zclconf/go-cty/cty"
)

// GenericSensitiveVariables See https://github.com/liamg/tfsec#included-checks for check info
const GenericSensitiveVariables Code = "GEN001"

func init() {
	RegisterCheck(Check{
		RequiredTypes: []string{"variable"},
		CheckFunc: func(block *parser.Block) []Result {

			if len(block.Labels()) == 0 {
				return nil
			}

			if !isSensitiveName(block.Labels()[0]) {
				return nil
			}

			var results []Result

			for _, attribute := range block.GetAttributes() {
				if attribute.Name() == "default" {
					val := attribute.Value()
					if val.Type() != cty.String {
						continue
					}
					if val.AsString() != "" {
						results = append(results, NewResult(
							GenericSensitiveVariables,
							fmt.Sprintf("Variable '%s' includes a potentially sensitive default value.", block.Name()),
							attribute.Range(),
						))
					}
				}
			}

			return results
		},
	})
}

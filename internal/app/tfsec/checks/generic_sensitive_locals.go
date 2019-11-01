package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
	"github.com/zclconf/go-cty/cty"
)

// GenericSensitiveLocals See https://github.com/liamg/tfsec#included-checks for check info
const GenericSensitiveLocals Code = "GEN002"

func init() {
	RegisterCheck(Check{
		RequiredTypes: []string{"locals"},
		CheckFunc: func(block *parser.Block) []Result {

			var results []Result

			for _, attribute := range block.GetAttributes() {
				if isSensitiveName(attribute.Name()) {
					if attribute.Type() == cty.String {
						results = append(results, NewResult(
							GenericSensitiveLocals,
							fmt.Sprintf("Local '%s' includes a potentially sensitive value which is defined within the project.", block.Name()),
							attribute.Range(),
						))
					}
				}
			}

			return results
		},
	})
}

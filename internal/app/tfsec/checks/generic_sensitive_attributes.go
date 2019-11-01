package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
	"github.com/zclconf/go-cty/cty"
)

// GenericSensitiveAttributes See https://github.com/liamg/tfsec#included-checks for check info
const GenericSensitiveAttributes Code = "GEN003"

func init() {
	RegisterCheck(Check{
		RequiredTypes: []string{"resource", "provider", "module"},
		CheckFunc: func(block *parser.Block) []Result {

			attributes := block.GetAttributes()

			var results []Result

			for _, attribute := range attributes {
				if isSensitiveName(attribute.Name()) {
					if attribute.Type() == cty.String {
						results = append(results, NewResult(
							GenericSensitiveAttributes,
							fmt.Sprintf("Block '%s' includes a potentially sensitive attribute which is defined within the project.", block.Name()),
							attribute.Range(),
						))
					}

				}
			}

			return results
		},
	})
}

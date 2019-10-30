package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/hashicorp/hcl/v2"
)

const GenericSensitiveAttributes Code = "GEN003"

func init() {
	RegisterCheck(Check{
		RequiredTypes: []string{"resource", "provider", "module"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {

			attributes, diag := block.Body.JustAttributes()
			if diag != nil && diag.HasErrors() {
				return nil
			}

			var results []Result

			for _, attribute := range attributes {
				if isSensitiveName(attribute.Name) {
					if val, diag := attribute.Expr.Value(ctx); diag == nil || !diag.HasErrors() {
						if val.Type() == cty.String {
							results = append(results, NewResult(
								GenericSensitiveAttributes,
								fmt.Sprintf("Block '%s' includes a potentially sensitive attribute which is defined within the project.", getBlockName(block)),
								convertRange(attribute.Range),
							))
						}
					}
				}
			}

			return results
		},
	})
}

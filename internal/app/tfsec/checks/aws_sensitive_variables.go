package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/hashicorp/hcl/v2"
	"github.com/liamg/tfsec/internal/app/tfsec/models"
)

func init() {
	RegisterCheck(Check{
		RequiredTypes: []string{"variable"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []models.Result {

			if len(block.Labels) == 0 {
				return nil
			}

			if !isSensitiveName(block.Labels[0]) {
				return nil
			}

			var results []models.Result

			attributes, _ := block.Body.JustAttributes()
			for _, attribute := range attributes {
				if attribute.Name == "default" {
					val, diag := attribute.Expr.Value(ctx)
					if diag != nil && diag.HasErrors() {
						continue
					}
					if val.Type() != cty.String {
						continue
					}
					if val.AsString() != "" {
						results = append(results, models.Result{
							Description: fmt.Sprintf("Variable '%s' includes a potentially sensitive default value.", getBlockName(block)),
						})
					}
				}
			}

			return results
		},
	})
}

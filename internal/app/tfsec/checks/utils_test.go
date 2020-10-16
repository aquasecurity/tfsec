package checks

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

func Test_isBooleanOrStringTrue(t *testing.T) {
	var tests = []struct {
		val     *parser.Attribute
		rawExpr string
		result  bool
	}{
		{
			rawExpr: "false",
			result:  false,
		},
		{
			rawExpr: "true",
			result:  true,
		},
		{
			rawExpr: `"false"`,
			result:  false,
		},
		{
			rawExpr: `"true"`,
			result:  true,
		},
		{
			rawExpr: `"foo"`,
			result:  false,
		},
		{
			rawExpr: "5",
			result:  false,
		},
	}

	for _, test := range tests {
		expr, _ := hclsyntax.ParseExpression([]byte(test.rawExpr), "", hcl.Pos{0, 0, 0})
		attr := parser.NewAttribute(
			&hclsyntax.Attribute{
				Expr: expr,
			},
			nil,
		)
		if result := isBooleanOrStringTrue(attr); result != test.result {
			t.Errorf("expected %v got %v\n", test.val, result)
		}
	}
}

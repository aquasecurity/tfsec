package checks

import (
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
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

func Test_isOpenCidr(t *testing.T) {
	var tests = []struct {
		val      *parser.Attribute
		rawExpr  string
		provider scanner.RuleProvider
		result   bool
	}{
		{
			rawExpr:  `["0.0.0.0/0"]`,
			provider: scanner.AWSProvider,
			result:   true,
		},
		{
			rawExpr:  `["1.2.3.4/0"]`,
			provider: scanner.AWSProvider,
			result:   true,
		},
		{
			rawExpr:  `["2620:0:2d0:200::7/0"]`,
			provider: scanner.AWSProvider,
			result:   true,
		},
		{
			rawExpr:  `["::/0"]`,
			provider: scanner.AWSProvider,
			result:   true,
		},
		{
			rawExpr:  `["1.2.3.5/32"]`,
			provider: scanner.AWSProvider,
			result:   false,
		},
		{
			rawExpr:  `["10.0.0.0/16"]`,
			provider: scanner.AWSProvider,
			result:   false,
		},
		{
			rawExpr:  `["2620:0:2d0:200::7/32"]`,
			provider: scanner.AWSProvider,
			result:   false,
		},
		{
			rawExpr:  `["172.16.32.0/20", "172.16.16.0/20", "172.16.0.0/20"]`,
			provider: scanner.AWSProvider,
			result:   false,
		},
		{
			rawExpr:  `["172.16.32.0/20", "172.16.16.0/20", "172.16.0.0/20", "0.0.0.0/0"]`,
			provider: scanner.AWSProvider,
			result:   true,
		},
		{
			rawExpr:  `["*"]`,
			provider: scanner.AWSProvider,
			result:   true,
		},

		// Azure
		{
			rawExpr:  `["10.0.0.0/16"]`,
			provider: scanner.AzureProvider,
			result:   false,
		},
		{
			rawExpr:  `["10.0.0.0/0"]`,
			provider: scanner.AzureProvider,
			result:   true,
		},
		{
			rawExpr:  `["*"]`,
			provider: scanner.AzureProvider,
			result:   true,
		},
		{
			rawExpr:  `"*"`,
			provider: scanner.AzureProvider,
			result:   true,
		},

		// GCP
		{
			rawExpr:  `["10.0.0.0/16"]`,
			provider: scanner.GCPProvider,
			result:   false,
		},
		{
			rawExpr:  `["10.0.0.0/0"]`,
			provider: scanner.GCPProvider,
			result:   true,
		},
		{
			rawExpr:  `["*"]`,
			provider: scanner.GCPProvider,
			result:   true,
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
		if result := isOpenCidr(attr, test.provider); result != test.result {
			t.Errorf("expected %v got %v\n", test.result, result)
		}
	}
}

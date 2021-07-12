package rules

import (
	"testing"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

func Test_isBooleanOrStringTrue(t *testing.T) {
	var tests = []struct {
		val     *block.Attribute
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
		expr, _ := hclsyntax.ParseExpression([]byte(test.rawExpr), "", hcl.Pos{Line: 0, Column: 0, Byte: 0})
		attr := block.NewHCLAttribute(
			&hcl.Attribute{
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
		val      *block.Attribute
		rawExpr  string
		provider provider.Provider
		result   bool
	}{
		{
			rawExpr:  `["0.0.0.0/0"]`,
			provider: provider.AWSProvider,
			result:   true,
		},
		{
			rawExpr:  `["1.2.3.4/0"]`,
			provider: provider.AWSProvider,
			result:   true,
		},
		{
			rawExpr:  `["2620:0:2d0:200::7/0"]`,
			provider: provider.AWSProvider,
			result:   true,
		},
		{
			rawExpr:  `["::/0"]`,
			provider: provider.AWSProvider,
			result:   true,
		},
		{
			rawExpr:  `["1.2.3.5/32"]`,
			provider: provider.AWSProvider,
			result:   false,
		},
		{
			rawExpr:  `["10.0.0.0/16"]`,
			provider: provider.AWSProvider,
			result:   false,
		},
		{
			rawExpr:  `["2620:0:2d0:200::7/32"]`,
			provider: provider.AWSProvider,
			result:   false,
		},
		{
			rawExpr:  `["172.16.32.0/20", "172.16.16.0/20", "172.16.0.0/20"]`,
			provider: provider.AWSProvider,
			result:   false,
		},
		{
			rawExpr:  `["172.16.32.0/20", "172.16.16.0/20", "172.16.0.0/20", "0.0.0.0/0"]`,
			provider: provider.AWSProvider,
			result:   true,
		},
		{
			rawExpr:  `["*"]`,
			provider: provider.AWSProvider,
			result:   true,
		},

		// Azure
		{
			rawExpr:  `["10.0.0.0/16"]`,
			provider: provider.AzureProvider,
			result:   false,
		},
		{
			rawExpr:  `["10.0.0.0/0"]`,
			provider: provider.AzureProvider,
			result:   true,
		},
		{
			rawExpr:  `["*"]`,
			provider: provider.AzureProvider,
			result:   true,
		},
		{
			rawExpr:  `"*"`,
			provider: provider.AzureProvider,
			result:   true,
		},

		// GCP
		{
			rawExpr:  `["10.0.0.0/16"]`,
			provider: provider.GCPProvider,
			result:   false,
		},
		{
			rawExpr:  `["10.0.0.0/0"]`,
			provider: provider.GCPProvider,
			result:   true,
		},
		{
			rawExpr:  `["*"]`,
			provider: provider.GCPProvider,
			result:   true,
		},
	}

	for _, test := range tests {
		expr, _ := hclsyntax.ParseExpression([]byte(test.rawExpr), "", hcl.Pos{Line: 0, Column: 0, Byte: 0})
		attr := block.NewHCLAttribute(
			&hcl.Attribute{
				Expr: expr,
			},
			nil,
		)
		if result := isOpenCidr(attr); result != test.result {
			t.Errorf("expected %v got %v\n", test.result, result)
		}
	}
}

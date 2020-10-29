package checks

import (
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"
	"strings"
)

// isBooleanOrStringTrue returns true if the attribute is a boolean and is
// `true` or if the attribute is a string and is `"true"`.
func isBooleanOrStringTrue(val *parser.Attribute) bool {
	switch val.Type() {
	case cty.Bool:
		return val.Value().True()
	case cty.String:
		return val.Value().Equals(cty.StringVal("true")).True()
	default:
		return false
	}
}

// isOpenCidr returns true if given attribute is an open CIDR block
func isOpenCidr(attr *parser.Attribute, provider scanner.RuleProvider) bool {
	if attr.Value().IsNull() {
		return false
	}

	var cidrList []cty.Value
	if attr.Type() == cty.String {
		cidrList = []cty.Value{attr.Value()}
	} else {
		cidrList = attr.Value().AsValueSlice()
	}

	for _, cidr := range cidrList {
		if cidr.Type() != cty.String {
			continue
		}

		cidrStr := cidr.AsString()
		if strings.HasSuffix(cidrStr, "/0") || cidrStr == "*" {
			return true
		}
	}

	return false
}

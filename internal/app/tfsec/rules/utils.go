package rules

import (
	"strings"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/zclconf/go-cty/cty"
)

// isBooleanOrStringTrue returns true if the attribute is a boolean and is
// `true` or if the attribute is a string and is `"true"`.
func isBooleanOrStringTrue(val block.Attribute) bool {
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
func isOpenCidr(attr block.Attribute) bool {
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

		if !cidr.IsKnown() {
			continue
		}

		cidrStr := cidr.AsString()
		if strings.HasSuffix(cidrStr, "/0") || cidrStr == "*" {
			return true
		}
	}

	return false
}

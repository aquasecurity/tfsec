package checks

import (
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/zclconf/go-cty/cty"
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

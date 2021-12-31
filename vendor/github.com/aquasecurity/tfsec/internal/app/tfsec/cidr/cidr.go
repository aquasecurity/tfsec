package cidr

import (
	"strings"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/zclconf/go-cty/cty"
)

func IsAttributeOpen(attr block.Attribute) bool {
	if attr.IsNil() || attr.Value().IsNull() {
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
		if IsOpen(cidrStr) {
			return true
		}
	}

	return false
}

func IsOpen(cidrStr string) bool {
	return strings.HasSuffix(cidrStr, "/0") || cidrStr == "*"
}

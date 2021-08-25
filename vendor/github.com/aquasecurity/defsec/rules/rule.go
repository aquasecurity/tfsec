package rules

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/severity"
)

type Rule struct {
	ID          string
	ShortCode   string
	Summary     string
	Explanation string
	Impact      string
	Resolution  string
	Provider    provider.Provider
	Service     string
	Links       []string
	Severity    severity.Severity
}

func (r Rule) LongID() string {
	return strings.ToLower(fmt.Sprintf("%s-%s-%s", r.Provider, r.Service, r.ShortCode))
}

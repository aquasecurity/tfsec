package rules

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/infra"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/result"
	"github.com/aquasecurity/defsec/severity"
)

type RuleDef struct {
	Id          string
	ShortCode   string
	Summary     string
	Explanation string
	Impact      string
	Resolution  string
	Provider    provider.Provider
	Service     string
	Links       []string
	Severity    severity.Severity
	CheckFunc   func(context *infra.Context) []*result.Result
}

func (r RuleDef) ID() string {
	return strings.ToLower(fmt.Sprintf("%s-%s-%s", r.Provider, r.Service, r.ShortCode))
}

func (r RuleDef) MatchesID(id string) bool {
	return r.ID() == id
}

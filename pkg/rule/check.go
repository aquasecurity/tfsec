package rule

import (
	"fmt"
	"os"
	runtimeDebug "runtime/debug"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/pkg/result"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

// CheckRule the provided HCL block against the rule
func CheckRule(r *Rule, block block.Block, ctx *hclcontext.Context) result.Set {
	defer func() {
		if err := recover(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "WARNING: skipped %s due to error(s): %s\n", r.ID, err)
			debug.Log("Stack trace for failed %s r:\n%s\n\n", r.ID, string(runtimeDebug.Stack()))
		}
	}()

	var links []string

	if r.Provider != provider.CustomProvider {
		links = append(links, fmt.Sprintf("https://tfsec.dev/docs/%s/%s/", r.Provider, r.ID))
	}

	links = append(links, r.Documentation.Links...)

	resultSet := result.NewSet().
		WithRuleID(r.ID).
		WithRuleSummary(r.Documentation.Summary).
		WithImpact(r.Documentation.Impact).
		WithResolution(r.Documentation.Resolution).
		WithRuleProvider(r.Provider).
		WithLinks(links)

	r.CheckFunc(resultSet, block, ctx)
	return resultSet
}

// IsRuleRequiredForBlock returns true if the Rule should be applied to the given HCL block
func IsRuleRequiredForBlock(rule *Rule, block block.Block) bool {

	if rule.CheckFunc == nil {
		return false
	}

	if len(rule.RequiredTypes) > 0 {
		var found bool
		for _, requiredType := range rule.RequiredTypes {
			if block.Type() == requiredType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(rule.RequiredLabels) > 0 {
		var found bool
		for _, requiredLabel := range rule.RequiredLabels {
			if requiredLabel == "*" || (len(block.Labels()) > 0 && wildcardMatch(requiredLabel, block.TypeLabel())) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func wildcardMatch(pattern string, subject string) bool {
	if pattern == "" {
		return false
	}
	parts := strings.Split(pattern, "*")
	var lastIndex int
	for i, part := range parts {
		if part == "" {
			continue
		}
		if i == 0 {
			if !strings.HasPrefix(subject, part) {
				return false
			}
		}
		if i == len(parts)-1 {
			if !strings.HasSuffix(subject, part) {
				return false
			}
		}
		newIndex := strings.Index(subject, part)
		if newIndex < lastIndex {
			return false
		}
		lastIndex = newIndex
	}
	return true
}

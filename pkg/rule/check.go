package rule

import (
	"fmt"
	"os"
	"path/filepath"
	runtimeDebug "runtime/debug"
	"strings"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/pkg/result"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

// CheckRule the provided HCL block against the rule
func CheckRule(r *Rule, resourceBlock block.Block, module block.Module, ignoreErrors bool) (resultSet result.Set) {
	if ignoreErrors {
		defer func() {
			if err := recover(); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "WARNING: skipped %s due to error(s): %s\n", r.ID(), err)
				debug.Log("Stack trace for failed %s r:\n%s\n\n", r.ID(), string(runtimeDebug.Stack()))
			}
		}()
	}

	var links []string
	if r.Provider != provider.CustomProvider {
		links = append(links, fmt.Sprintf("https://aquasecurity.github.io/tfsec/latest/checks/%s/%s/%s", r.Provider, r.Service, r.ShortCode))
	}

	links = append(links, r.Documentation.Links...)

	resultSet = result.NewSet(resourceBlock).
		WithRuleID(r.ID()).
		WithLegacyRuleID(r.LegacyID).
		WithRuleSummary(r.Documentation.Summary).
		WithImpact(r.Documentation.Impact).
		WithResolution(r.Documentation.Resolution).
		WithRuleProvider(r.Provider).
		WithRuleService(r.Service).
		WithLinks(links)

	r.CheckFunc(resultSet, resourceBlock, module)
	return resultSet
}

// IsRuleRequiredForBlock returns true if the Rule should be applied to the given HCL block
func IsRuleRequiredForBlock(rule *Rule, b block.Block) bool {

	if rule.CheckFunc == nil {
		return false
	}

	if len(rule.RequiredTypes) > 0 {
		if !checkRequiredTypesMatch(rule, b) {
			return false
		}
	}

	if len(rule.RequiredLabels) > 0 {
		if !checkRequiredLabelsMatch(rule, b) {
			return false
		}

	}

	if len(rule.RequiredSources) > 0 && b.Type() == block.TypeModule.Name() {
		if !checkRequiredSourcesMatch(rule, b) {
			return false
		}
	}

	return true
}

func checkRequiredTypesMatch(rule *Rule, b block.Block) bool {
	var found bool
	for _, requiredType := range rule.RequiredTypes {
		if b.Type() == requiredType {
			found = true
			break
		}
	}

	return found
}

func checkRequiredLabelsMatch(rule *Rule, b block.Block) bool {
	var found bool
	for _, requiredLabel := range rule.RequiredLabels {
		if requiredLabel == "*" || (len(b.Labels()) > 0 && wildcardMatch(requiredLabel, b.TypeLabel())) {
			found = true
			break
		}
	}

	return found
}

func checkRequiredSourcesMatch(rule *Rule, b block.Block) bool {
	var found bool
	if sourceAttr := b.GetAttribute("source"); sourceAttr.IsNotNil() {
		sourcePath := sourceAttr.ValueAsStrings()[0]

		// resolve module source path to path relative to cwd
		if strings.HasPrefix(sourcePath, ".") {
			var err error
			sourcePath, err = cleanPathRelativeToWorkingDir(filepath.Dir(b.Range().Filename), sourcePath)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "WARNING: did not path for module %s due to error(s): %s\n", fmt.Sprintf("%s:%s", b.FullName(), b.Range().Filename), err)
			}
		}

		for _, requiredSource := range rule.RequiredSources {
			if requiredSource == "*" || wildcardMatch(requiredSource, sourcePath) {
				found = true
				break
			}
		}
	}

	return found
}

func cleanPathRelativeToWorkingDir(dir, path string) (string, error) {
	absPath := filepath.Clean(filepath.Join(dir, path))

	wDir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	if !strings.HasSuffix(wDir, "/") {
		wDir = filepath.Join(wDir, "/")
	}

	relPath, err := filepath.Rel(wDir, absPath)
	if err != nil {
		return "", err
	}

	return relPath, nil
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

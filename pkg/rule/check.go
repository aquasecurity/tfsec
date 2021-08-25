package rule

import (
	"fmt"
	"os"
	"path/filepath"
	runtimeDebug "runtime/debug"
	"strings"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
)

func (r *Rule) createResultSet() types.Results {
	var links []string
	if r.DefSecCheck.Provider != provider.CustomProvider {
		links = append(links, fmt.Sprintf(
			"https://tfsec.dev/docs/%s/%s/%s#%s/%s",
			r.DefSecCheck.Provider,
			r.DefSecCheck.Service,
			r.DefSecCheck.ShortCode,
			r.DefSecCheck.Provider,
			r.DefSecCheck.Service,
		))
	}
	return result.NewSet().
		WithRuleID(r.ID()).
		WithLegacyRuleID(r.LegacyID).
		WithRuleSummary(r.DefSecCheck.Summary).
		WithImpact(r.DefSecCheck.Impact).
		WithResolution(r.DefSecCheck.Resolution).
		WithRuleProvider(r.DefSecCheck.Provider).
		WithSeverity(r.DefSecCheck.Severity).
		WithLinks(append(links, r.Links...))

}

func (r *Rule) CheckAgainstContext(context *state.State) types.Results {

	set := r.createResultSet()

	if r.DefSecCheck.CheckFunc == nil {
		return set
	}

	for _, result := range r.DefSecCheck.CheckFunc(context) {
		set.Add(result)
	}

	return set

}

func (r *Rule) RecoverFromCheckPanic() {
	if err := recover(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "WARNING: skipped %s due to error(s): %s\n", r.ID(), err)
		debug.Log("Stack trace for failed %s r:\n%s\n\n", r.ID(), string(runtimeDebug.Stack()))
	}
}

func (r *Rule) CheckAgainstBlock(b block.Block, m block.Module) types.Results {
	set := r.createResultSet()
	if r.CheckTerraform == nil {
		return set
	}
	if r.isRuleRequiredForBlock(b) {
		r.CheckTerraform(set, b, m)
	}
	return set
}

// IsRuleRequiredForBlock returns true if the Rule should be applied to the given HCL block
func (r *Rule) isRuleRequiredForBlock(b block.Block) bool {

	if len(r.RequiredTypes) > 0 {
		if !r.checkRequiredTypesMatch(b) {
			return false
		}
	}

	if len(r.RequiredLabels) > 0 {
		if !r.checkRequiredLabelsMatch(b) {
			return false
		}

	}

	if len(r.RequiredSources) > 0 && b.Type() == block.TypeModule.Name() {
		if !r.checkRequiredSourcesMatch(b) {
			return false
		}
	}

	return true
}

func (r *Rule) checkRequiredTypesMatch(b block.Block) bool {
	var found bool
	for _, requiredType := range r.RequiredTypes {
		if b.Type() == requiredType {
			found = true
			break
		}
	}

	return found
}

func (r *Rule) checkRequiredLabelsMatch(b block.Block) bool {
	var found bool
	for _, requiredLabel := range r.RequiredLabels {
		if requiredLabel == "*" || (len(b.Labels()) > 0 && wildcardMatch(requiredLabel, b.TypeLabel())) {
			found = true
			break
		}
	}

	return found
}

func (r *Rule) checkRequiredSourcesMatch(b block.Block) bool {
	var found bool
	if sourceAttr := b.GetAttribute("source"); sourceAttr.IsNotNil() {
		sourcePath := sourceAttr.ValueAsStrings()[0]

		// resolve module source path to path relative to cwd
		if strings.HasPrefix(sourcePath, ".") {
			var err error
			sourcePath, err = cleanPathRelativeToWorkingDir(filepath.Dir(b.Range().Filename), sourcePath)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "WARNING: did not clean path for module %s due to error(s): %s\n", fmt.Sprintf("%s:%s", b.FullName(), b.Range().Filename), err)
			}
		}

		for _, requiredSource := range r.RequiredSources {
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

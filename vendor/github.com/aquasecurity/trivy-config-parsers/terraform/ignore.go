package terraform

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/zclconf/go-cty/cty"
)

type Ignore struct {
	Range     types.Range
	RuleID    string
	Expiry    *time.Time
	Workspace string
	Block     bool
	Params    map[string]string
}

type Ignores []Ignore

func (ignores Ignores) Covering(modules Modules, m types.Metadata, workspace string, ids ...string) *Ignore {
	for _, ignore := range ignores {
		if ignore.Covering(modules, m, workspace, ids...) {
			return &ignore
		}
	}
	return nil
}

func (ignore Ignore) Covering(modules Modules, m types.Metadata, workspace string, ids ...string) bool {
	if ignore.Expiry != nil && time.Now().After(*ignore.Expiry) {
		return false
	}
	if ignore.Workspace != "" && ignore.Workspace != workspace {
		return false
	}
	idMatch := ignore.RuleID == "*" || len(ids) == 0
	for _, id := range ids {
		if id == ignore.RuleID {
			idMatch = true
			break
		}
	}
	if !idMatch {
		return false
	}

	metaHierarchy := &m
	for metaHierarchy != nil {
		if metaHierarchy.Range() == nil {
			fmt.Fprintf(os.Stderr, "WARNING: Missing range for result from result with IDs: %s\n", strings.Join(ids, ", "))
			break
		}
		if ignore.Range.GetFilename() != metaHierarchy.Range().GetFilename() {
			metaHierarchy = metaHierarchy.Parent()
			continue
		}
		if metaHierarchy.Range().GetStartLine() == ignore.Range.GetStartLine()+1 || metaHierarchy.Range().GetStartLine() == ignore.Range.GetStartLine() {
			return ignore.MatchParams(modules)
		}
		metaHierarchy = metaHierarchy.Parent()
	}
	return false

}

func (ignore Ignore) MatchParams(modules Modules) bool {
	if len(ignore.Params) == 0 {
		return true
	}
	block := modules.GetBlockByIgnoreRange(ignore.Range)
	if block == nil {
		return true
	}
	for key, val := range ignore.Params {
		attr := block.GetAttribute(key)
		if attr.IsNil() || !attr.Value().IsKnown() {
			return false
		}
		switch attr.Type() {
		case cty.String:
			if !attr.Equals(val) {
				return false
			}
		case cty.Number:
			bf := attr.Value().AsBigFloat()
			f64, _ := bf.Float64()
			comparableInt := fmt.Sprintf("%d", int(f64))
			comparableFloat := fmt.Sprintf("%f", f64)
			if val != comparableInt && val != comparableFloat {
				return false
			}
		case cty.Bool:
			if fmt.Sprintf("%t", attr.IsTrue()) != val {
				return false
			}
		default:
			return false
		}
	}
	return true
}

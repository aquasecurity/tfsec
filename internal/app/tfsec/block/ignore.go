package block

import (
	"time"

	"github.com/aquasecurity/defsec/types"
)

type Ignore struct {
	ModuleKey string //  whether the ignore applies to the whole module
	Range     HCLRange
	RuleID    string
	Expiry    *time.Time
	Workspace string
}

type Ignores []Ignore

func (ignores Ignores) Covering(r types.Range, workspace string, ids ...string) *Ignore {
	for _, ignore := range ignores {
		if ignore.Covering(r, workspace, ids...) {
			return &ignore
		}
	}
	return nil
}

func (ignore Ignore) Covering(r types.Range, workspace string, ids ...string) bool {
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
	rng, ok := r.(HCLRange)
	if !ok {
		return false
	}
	if ignore.ModuleKey != "" && ignore.ModuleKey == rng.GetModule() {
		return true
	}
	if ignore.Range.GetFilename() != r.GetFilename() {
		return false
	}
	if r.GetStartLine() == ignore.Range.GetStartLine()+1 || r.GetStartLine() == ignore.Range.GetStartLine() {
		return true
	}
	return false

}

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

func (i Ignores) Covering(r types.Range, workspace string, ids ...string) *Ignore {

	rng := r.(HCLRange)

	for _, ignore := range i {
		if ignore.Expiry != nil && time.Now().After(*ignore.Expiry) {
			continue
		}
		if ignore.Workspace != "" && ignore.Workspace != workspace {
			continue
		}
		idMatch := ignore.RuleID == "*" || len(ids) == 0
		if !idMatch {
			for _, id := range ids {
				if id == ignore.RuleID {
					idMatch = true
					break
				}
			}
		}
		if !idMatch {
			continue
		}
		if ignore.ModuleKey != "" && ignore.ModuleKey == rng.GetModule() {
			return &ignore
		}
		if ignore.Range.GetFilename() != r.GetFilename() {
			continue
		}
		if r.GetStartLine() == ignore.Range.GetStartLine()+1 || r.GetStartLine() == ignore.Range.GetStartLine() {
			return &ignore
		}
	}
	return nil
}

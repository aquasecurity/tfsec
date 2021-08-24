package block

import (
	"time"

	"github.com/aquasecurity/defsec/definition"
)

type Ignore struct {
	ModuleKey string //  whether the ignore applies to the whole module
	Range     HCLRange
	RuleID    string
	Expiry    *time.Time
	Workspace string
}

type Ignores []Ignore

func (i Ignores) Covering(r definition.Range, workspace string, ids ...string) *Ignore {
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
		if ignore.ModuleKey != "" && ignore.ModuleKey == r.GetModule() {
			return &ignore
		}
		if ignore.Range.Filename != r.GetFilename() {
			continue
		}
		if r.GetStartLine() == ignore.Range.StartLine+1 || r.GetStartLine() == ignore.Range.StartLine {
			return &ignore
		}
	}
	return nil
}

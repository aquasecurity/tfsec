package block

import (
	"time"

	"github.com/aquasecurity/defsec/definition"
)

type Ignore struct {
	ModuleWide string // whether the ignore applies to the whole module
	Range      HCLRange
	RuleID     string
	Expiry     *time.Time
	Workspace  string
}

type Ignores []Ignore

func (i Ignores) Covering(ids []string, r definition.Range) *Ignore {
	if r == nil {
		panic(999)
	}
	for _, ignore := range i {
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
		if ignore.ModuleWide != "" && ignore.ModuleWide == r.GetModule() {
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

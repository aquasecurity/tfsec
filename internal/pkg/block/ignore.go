package block

import (
	"fmt"
	"time"

	"github.com/aquasecurity/defsec/types"
)

type Ignore struct {
	Range     types.Range
	RuleID    string
	Expiry    *time.Time
	Workspace string
	Block     bool
}

type Ignores []Ignore

func (ignores Ignores) Covering(m *types.Metadata, workspace string, ids ...string) *Ignore {
	for _, ignore := range ignores {
		if ignore.Covering(m, workspace, ids...) {
			return &ignore
		}
	}
	return nil
}

func (ignore Ignore) Covering(m *types.Metadata, workspace string, ids ...string) bool {
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

	for m != nil {
		fmt.Printf("Actual: %s\nIgnore: %s\n", m, ignore.Range)

		if ignore.Range.GetFilename() != m.Range().GetFilename() {
			m = m.Parent()
			continue
		}
		if m.Range().GetStartLine() == ignore.Range.GetStartLine()+1 || m.Range().GetStartLine() == ignore.Range.GetStartLine() {
			return true
		}
		m = m.Parent()
	}
	return false

}

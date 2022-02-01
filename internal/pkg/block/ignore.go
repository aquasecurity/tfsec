package block

import (
	"fmt"
	"os"
	"strings"
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

func (ignores Ignores) Covering(m types.Metadata, workspace string, ids ...string) *Ignore {
	for _, ignore := range ignores {
		if ignore.Covering(m, workspace, ids...) {
			return &ignore
		}
	}
	return nil
}

func (ignore Ignore) Covering(m types.Metadata, workspace string, ids ...string) bool {
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
			return true
		}
		metaHierarchy = metaHierarchy.Parent()
	}
	return false

}

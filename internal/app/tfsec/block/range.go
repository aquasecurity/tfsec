package block

import (
	"github.com/aquasecurity/defsec/types"
)

// HCLRange describes an area of code, including the filename it is present in and the lin numbers the code occupies
type HCLRange struct {
	base   types.Range
	module string
}

func NewRange(f string, startLine int, endLine int, module string) HCLRange {
	return HCLRange{
		base:   types.NewRange(f, startLine, endLine),
		module: module,
	}
}

func (r HCLRange) GetFilename() string {
	return r.base.GetFilename()
}

func (r HCLRange) GetModule() string {
	return r.module
}

func (r HCLRange) GetStartLine() int {
	return r.base.GetStartLine()
}

func (r HCLRange) GetEndLine() int {
	return r.base.GetEndLine()
}

func (r HCLRange) String() string {
	return r.base.String()
}

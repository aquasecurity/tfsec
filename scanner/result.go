package scanner

import (
	"github.com/hashicorp/hcl/hcl/token"
)

type Result struct {
	pos         token.Pos
	description string
}

func NewResult(pos token.Pos, description string) *Result {
	return &Result{
		pos:         pos,
		description: description,
	}
}

func (r Result) Description() string {
	return r.description
}

func (r Result) Line() int {
	return r.pos.Line
}

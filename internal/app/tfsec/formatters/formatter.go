package formatters

import (
	"io"

	"github.com/aquasecurity/defsec/types"
)

type FormatterOption int

const (
	ConciseOutput FormatterOption = iota
	IncludePassed
	PassingGif
)

// Formatter formats scan results into a specific format
type Formatter func(w io.Writer, results []types.Result, baseDir string, options ...FormatterOption) error

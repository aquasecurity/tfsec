package formatters

import (
	"io"

	"github.com/aquasecurity/defsec/rules"
)

type FormatterOption int

const (
	ConciseOutput FormatterOption = iota
	PassingGif
	NoColour
	WithDebug
)

// Formatter formats scan results into a specific format
type Formatter func(w io.Writer, results []rules.Result, baseDir string, options ...FormatterOption) error

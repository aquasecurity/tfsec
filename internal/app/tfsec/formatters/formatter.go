package formatters

import (
	"io"

	"github.com/aquasecurity/defsec/result"
)

type FormatterOption int

const (
	ConciseOutput FormatterOption = iota
	IncludePassed
	PassingGif
)

// Formatter formats scan results into a specific format
type Formatter func(w io.Writer, results []result.Result, baseDir string, options ...FormatterOption) error

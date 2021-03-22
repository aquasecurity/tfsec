package formatters

import (
	"io"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

type FormatterOption int

const (
	ConciseOutput FormatterOption = iota
	IncludePassed FormatterOption = iota
)

// Formatter formats scan results into a specific format
type Formatter func(w io.Writer, results []scanner.Result, baseDir string, options ...FormatterOption) error

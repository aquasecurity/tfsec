package formatters

import (
	"io"

	"github.com/aquasecurity/tfsec/pkg/result"
)

type FormatterOption int

const (
	ConciseOutput FormatterOption = iota
	IncludePassed
)

// Formatter formats scan results into a specific format
type Formatter func(w io.Writer, results []result.Result, baseDir string, options ...FormatterOption) error

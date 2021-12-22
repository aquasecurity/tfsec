package formatters

import (
	"io"

	"github.com/aquasecurity/defsec/rules"
)

func FormatGif(w io.Writer, results []rules.Result, baseDir string, options ...FormatterOption) error {
	return FormatDefault(w, results, baseDir, append(options, PassingGif)...)
}

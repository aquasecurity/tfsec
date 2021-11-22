package formatters

import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"io"
)

func FormatGif(w io.Writer, results []result.Result, baseDir string, options ...FormatterOption) error {
	return FormatDefault(w, results, baseDir, append(options, PassingGif)...)
}
